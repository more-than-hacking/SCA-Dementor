# server.py
import os
import logging
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Dict

from flask import Flask, request, jsonify, send_from_directory, Response, stream_with_context, make_response
from dotenv import load_dotenv
import yaml
import requests as http_requests

from dementor_sca import REPO_ROOT
from dementor_sca.pr_creation import create_pr_with_llm_update, HTTPException as PRCreationHTTPException
from dementor_sca.reachability_scan import scan_for_reachability, API_CLONED_REPOS_PARENT as REACH_CLONED_REPOS_PARENT
import dementor_sca.scan_runner as scan_runner

# --- CONFIGURATION ---
load_dotenv()

script_dir = REPO_ROOT

def load_config(yaml_path=None):
    """
    Loads configuration from a YAML file. Optional: if file missing or keys missing,
    returns a dict with empty values so the dashboard can run (view-only). API endpoints
    that need GitHub will check and return 503 when token/org are missing.
    """
    if yaml_path is None:
        yaml_path = os.getenv("CONFIG_YAML_PATH", str(script_dir / "config" / "org_config.yaml"))
    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f) or {}
            config.setdefault("GITHUB_TOKEN", "")
            config.setdefault("org_name", "")
            return config
    except FileNotFoundError:
        return {"GITHUB_TOKEN": "", "org_name": ""}
    except yaml.YAMLError as e:
        logging.warning(f"Error parsing YAML config: {e}. Using empty config (dashboard-only).")
        return {"GITHUB_TOKEN": "", "org_name": ""}

# Cache the configuration to avoid repeated file reads
_cached_config = None

def get_config():
    """Retrieves the cached configuration or loads it if not already cached."""
    global _cached_config
    if _cached_config is None:
        _cached_config = load_config()
    return _cached_config

config = get_config()

# Global Constants from Config
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN") or config.get("GITHUB_TOKEN") or ""
ORG_NAME = config.get("org_name") or ""
LLM_MODEL = os.getenv("LLM_MODEL", "cursor-proxy")  # resolved by llm_client at call time


CONFIG_YAML_PATH = Path(os.getenv("CONFIG_YAML_PATH", str(script_dir / "config" / "org_config.yaml")))


def _require_github_config():
    """Raise or return 503 response if token/org not set (for API endpoints that need them)."""
    if not GITHUB_TOKEN or not ORG_NAME:
        from flask import make_response
        return make_response(jsonify({"error": "GITHUB_TOKEN and org_name required for this action. Set config/org_config.yaml or env vars."}), 503)
    return None


def _reload_runtime_config():
    """Re-read org_config.yaml and refresh the module-level token/org globals."""
    global GITHUB_TOKEN, ORG_NAME, _cached_config
    _cached_config = None
    fresh = load_config()
    _cached_config = fresh
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN") or fresh.get("GITHUB_TOKEN") or fresh.get("github", {}).get("token") or ""
    ORG_NAME = fresh.get("org_name") or fresh.get("github", {}).get("org_name") or ""


# --- Constants for Dashboard Data File Path ---
VULNERABILITY_REPORT_PATH = REPO_ROOT / "vulnerability_report_live_verified.json"
REPOSITORIES_DIR = REPO_ROOT / "REPOSITORIES"

# --- Flask Setup ---
app = Flask(__name__)
# Upload limits for repo uploads (folder = many files, or a .zip):
#  - total size cap (DEMENTOR_MAX_UPLOAD_MB, default 500 MB)
#  - Werkzeug 3.1+ defaults MAX_FORM_PARTS to 1000, which rejects a folder upload with
#    >1000 files (each file is a form part) with HTTP 413. Raise it for real repos.
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("DEMENTOR_MAX_UPLOAD_MB", "500")) * 1024 * 1024
app.config["MAX_FORM_PARTS"] = int(os.getenv("DEMENTOR_MAX_UPLOAD_FILES", "50000"))
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# --- Functions for reading/writing vulnerability data file (kept here as server manages it) ---
def read_vulnerability_data() -> List[Dict]:
    """Reads the vulnerability data from the JSON file."""
    if not VULNERABILITY_REPORT_PATH.exists():
        logging.warning(f"Vulnerability report file not found at {VULNERABILITY_REPORT_PATH}. Returning empty list.")
        return []
    try:
        with open(VULNERABILITY_REPORT_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from {VULNERABILITY_REPORT_PATH}: {e}")
        return []
    except Exception as e:
        logging.error(f"Error reading {VULNERABILITY_REPORT_PATH}: {e}")
        return []

def write_vulnerability_data(data: List[Dict]):
    """Writes the updated vulnerability data to the JSON file."""
    try:
        VULNERABILITY_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write: serialize to a temp file, then os.replace() — so an interrupted or
        # overlapping write can never truncate/corrupt the live report (the findings DB).
        tmp = VULNERABILITY_REPORT_PATH.with_suffix(VULNERABILITY_REPORT_PATH.suffix + ".tmp")
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        os.replace(tmp, VULNERABILITY_REPORT_PATH)
        logging.info(f"Successfully wrote updated vulnerability data to {VULNERABILITY_REPORT_PATH}")
    except Exception as e:
        logging.error(f"Error writing to {VULNERABILITY_REPORT_PATH}: {e}")
        raise

# --- API Endpoints ---
@app.route('/api/create-pr', methods=['POST'])
def api_create_pr():
    """
    Handles PR creation requests.
    Expects a JSON payload with repository and library details.
    """
    err = _require_github_config()
    if err is not None:
        return err
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        required = ['repo_owner', 'repo_name', 'file_path_in_repo',
                  'library', 'version_in_use', 'upgrade_recommendation']
        if missing := [f for f in required if f not in data]:
            return jsonify({"error": f"Missing fields: {missing}"}), 400

        if 'minimal_safer_version' not in data['upgrade_recommendation']:
            return jsonify({"error": "Missing target version in upgrade_recommendation"}), 400

        logging.info(f"Received PR creation request for {data['library']} in {data['repo_owner']}/{data['repo_name']}")

        pr_url = create_pr_with_llm_update(
            github_token=GITHUB_TOKEN,
            repo_owner=data['repo_owner'],
            repo_name=data['repo_name'],
            file_path=data['file_path_in_repo'],
            library_name=data['library'],
            current_ver=data['version_in_use'],
            new_ver=data['upgrade_recommendation']['minimal_safer_version']
        )

        return jsonify({
            "status": "success",
            "pr_url": pr_url,
            "timestamp": datetime.now().isoformat()
        }), 200

    except ValueError as ve:
        logging.warning(f"API create-pr request resulted in no changes: {str(ve)}")
        return jsonify({"status": "no_changes", "message": str(ve)}), 200
    except PRCreationHTTPException as he:
        logging.error(f"HTTP error in /api/create-pr: {he.detail}", exc_info=True)
        return jsonify({"error": he.detail}), he.status_code
    except Exception as e:
        logging.error(f"API error in /api/create-pr: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan-reachability', methods=['POST'])
def api_scan_reachability():
    """
    Analyzes the reachability and vulnerability confirmation for a list of libraries
    within their respective GitHub repositories.
    If the repo already exists in REPOSITORIES/, no GitHub credentials are needed.
    GitHub credentials are only required when a remote clone is necessary.
    """
    try:
        libraries_to_scan = request.get_json()
        if not isinstance(libraries_to_scan, list):
            return jsonify({"error": "Request body must be a JSON array of library entries."}), 400

        # REACH_CLONED_REPOS_PARENT will be SCA_CLONED_REPOS as imported from reachability_scan.py
        REACH_CLONED_REPOS_PARENT.mkdir(parents=True, exist_ok=True) 

        current_vulnerability_data = read_vulnerability_data()
        data_map = {(entry['library'], entry['file_location']): entry for entry in current_vulnerability_data}

        def _scan_one_entry(entry_data_from_client: Dict) -> Dict:
            """Scan a single library entry; returns the entry dict with scan results merged in."""
            result = dict(entry_data_from_client)

            # Backfill ecosystem from the stored report so reachability is scoped to the dep's own
            # language (npm ≠ PyPI) even when the client didn't send it.
            if not result.get("ecosystem"):
                stored = data_map.get((result.get("library"), result.get("file_location")))
                if stored and stored.get("ecosystem"):
                    result["ecosystem"] = stored["ecosystem"]

            if not all(k in result for k in ['library', 'file_location', 'vulnerabilities']):
                logging.warning(f"Skipping malformed entry: {result}. Missing required keys.")
                result.update({
                    "is_used": False, "llm_confirms_vuln": False,
                    "evidence": [], "scan_error": "Malformed input entry, missing 'library', 'file_location', or 'vulnerabilities'"
                })
                return result

            if not isinstance(result['vulnerabilities'], list):
                result['vulnerabilities'] = []

            for vuln in result['vulnerabilities']:
                if 'details' not in vuln:
                    logging.warning(f"Vulnerability entry missing 'details': {vuln}")
                if 'vulnerability_usage_analysis' not in vuln or not isinstance(vuln['vulnerability_usage_analysis'], list):
                    vuln['vulnerability_usage_analysis'] = []

            logging.info(f"\n[scan] {result['library']} v{result.get('version_in_use','?')} — starting reachability scan")

            try:
                original_file_path_obj = Path(result['file_location'])
                try:
                    repositories_index = original_file_path_obj.parts.index('REPOSITORIES')
                except ValueError:
                    raise ValueError(
                        f"'file_location' path '{result['file_location']}' does not contain 'REPOSITORIES' segment."
                    )

                if len(original_file_path_obj.parts) <= repositories_index + 1:
                    raise ValueError(f"Could not extract repo name from path: {result['file_location']}")

                github_repo_name = original_file_path_obj.parts[repositories_index + 1]
                if not github_repo_name:
                    raise ValueError(f"Empty repo name extracted from '{result['file_location']}'.")

                relative_path_within_repo = Path(*original_file_path_obj.parts[repositories_index + 2:])
                local_repo_path = REPOSITORIES_DIR / github_repo_name

                if local_repo_path.is_dir():
                    result['file_location_in_cloned_repo'] = str(local_repo_path / relative_path_within_repo)
                    scan_output = scan_for_reachability(
                        github_token=GITHUB_TOKEN,
                        org_name=ORG_NAME,
                        library_entry_data=result,
                        github_repo_name=github_repo_name,
                        local_repo_path=str(local_repo_path),
                    )
                else:
                    if not GITHUB_TOKEN or not ORG_NAME:
                        raise ValueError(
                            f"Repository '{github_repo_name}' not found in local REPOSITORIES/. "
                            "Set GITHUB_TOKEN and ORG_NAME to clone it from GitHub."
                        )
                    result['file_location_in_cloned_repo'] = str(
                        REACH_CLONED_REPOS_PARENT / github_repo_name / relative_path_within_repo
                    )
                    scan_output = scan_for_reachability(
                        github_token=GITHUB_TOKEN,
                        org_name=ORG_NAME,
                        library_entry_data=result,
                        github_repo_name=github_repo_name,
                    )
                result.update(scan_output)
                logging.info(f"[scan] {result['library']} — done. exploitable={result.get('llm_confirms_vuln', False)}")

            except Exception as e:
                error_message = f"[!] Error scanning {result.get('library','unknown')}: {type(e).__name__}: {e}"
                logging.error(error_message, exc_info=True)
                result.update({
                    "is_used": False,
                    "llm_confirms_vuln": False,
                    "evidence": [],
                    "scan_error": error_message,
                    "reachability_analysis": {
                        "declared": True, "imported": False,
                        "vulnerable_api_used": False,
                        "notes": f"Scan error: {error_message}",
                    },
                })
            return result

        # Run per-library scans in parallel — each library is independent.
        # Worker count: min(#libraries, 4) so we don't overwhelm the LLM proxy with too many simultaneous calls.
        # More workers = faster full scan (more concurrent LLM calls). Cap at 6 to avoid overwhelming the proxy.
        max_workers = min(len(libraries_to_scan), 6)
        logging.info(f"[scan] Starting parallel reachability scan: {len(libraries_to_scan)} libraries, {max_workers} workers")

        processed_results_for_client: List[Dict] = [None] * len(libraries_to_scan)  # preserve order
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_idx = {pool.submit(_scan_one_entry, entry): i for i, entry in enumerate(libraries_to_scan)}
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    processed_results_for_client[idx] = future.result()
                except Exception as exc:
                    entry = libraries_to_scan[idx]
                    logging.error(f"[scan] Unexpected worker error for {entry.get('library','?')}: {exc}", exc_info=True)
                    processed_results_for_client[idx] = dict(entry, is_used=False, llm_confirms_vuln=False,
                                                              evidence=[], scan_error=str(exc))

        # Update the data map and persist
        for entry in processed_results_for_client:
            if entry:
                data_map[(entry['library'], entry['file_location'])] = entry

        write_vulnerability_data(list(data_map.values()))
        logging.info(f"\n✓ Reachability scan complete ({len(processed_results_for_client)} libraries). '{VULNERABILITY_REPORT_PATH.name}' updated.")
        return jsonify(processed_results_for_client), 200

    except Exception as e:
        logging.error(f"API error in /api/scan-reachability: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ── Config API ────────────────────────────────────────────────────────────────

@app.route('/api/config', methods=['GET'])
def api_get_config():
    """
    Return the current org_config.yaml as JSON.
    GitHub token and LLM api_key are masked — only *_set booleans are returned.
    """
    try:
        raw = load_config()
        token = (
            os.getenv("GITHUB_TOKEN")
            or raw.get("GITHUB_TOKEN")
            or raw.get("github", {}).get("token")
            or ""
        )
        org = raw.get("org_name") or raw.get("github", {}).get("org_name") or ""
        scan_cfg = raw.get("scan", {})
        llm_cfg  = raw.get("llm", {}) or {}
        return jsonify({
            "org":       org,
            "token_set": bool(token),
            "scan": {
                "mode":              scan_cfg.get("mode", "single"),
                "repos":             scan_cfg.get("repos") or [],
                "max_repos":         scan_cfg.get("max_repos", 0),
                "skip_reachability": scan_cfg.get("skip_reachability", False),
            },
            "llm": {
                "provider":    llm_cfg.get("provider", "cursor"),
                "api_url":     llm_cfg.get("api_url", ""),
                "api_key_set": bool(llm_cfg.get("api_key") or os.getenv("LLM_API_KEY", "")),
                "model":       llm_cfg.get("model", ""),
            },
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/config', methods=['POST'])
def api_save_config():
    """
    Save posted JSON config back to org_config.yaml.
    Accepts: { org, token, scan: {...}, llm: { provider, api_url, api_key, model } }
    Blank / omitted secrets (token, api_key) preserve the existing value in the file.
    """
    try:
        from dementor_sca.llm_client import invalidate_config_cache
        data = request.get_json() or {}

        # Load existing file so we don't clobber unrelated keys
        existing: dict = {}
        if CONFIG_YAML_PATH.exists():
            with open(CONFIG_YAML_PATH, "r") as f:
                existing = yaml.safe_load(f) or {}

        # ── GitHub credentials ────────────────────────────────────────────────
        new_token = (data.get("token") or "").strip()
        old_token = (
            existing.get("GITHUB_TOKEN")
            or existing.get("github", {}).get("token")
            or ""
        )
        token_to_save = new_token if new_token else old_token
        org = (data.get("org") or "").strip()

        # ── Scan settings ─────────────────────────────────────────────────────
        scan_in = data.get("scan", {})

        # ── LLM settings ──────────────────────────────────────────────────────
        llm_in      = data.get("llm", {}) or {}
        old_llm     = existing.get("llm", {}) or {}
        new_api_key = (llm_in.get("api_key") or "").strip()
        old_api_key = (old_llm.get("api_key") or "").strip()
        llm_to_save = {
            "provider": (llm_in.get("provider") or old_llm.get("provider") or "cursor").strip(),
            "api_url":  (llm_in.get("api_url")  or old_llm.get("api_url")  or "").strip(),
            "api_key":  new_api_key if new_api_key else old_api_key,
            "model":    (llm_in.get("model")    or old_llm.get("model")    or "").strip(),
        }

        updated = {
            "github": {"org_name": org, "token": token_to_save},
            "org_name":     org,
            "GITHUB_TOKEN": token_to_save,
            "scan": {
                "mode":              scan_in.get("mode", "single"),
                "repos":             scan_in.get("repos") or [],
                "max_repos":         int(scan_in.get("max_repos") or 0),
                "skip_reachability": bool(scan_in.get("skip_reachability", False)),
            },
            "llm": llm_to_save,
        }

        # Preserve any other top-level keys we don't own (e.g. parser settings)
        for k, v in existing.items():
            if k not in updated:
                updated[k] = v

        CONFIG_YAML_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_YAML_PATH, "w") as f:
            yaml.dump(updated, f, default_flow_style=False, sort_keys=False)

        _reload_runtime_config()
        invalidate_config_cache()   # flush llm_client's in-memory cache
        logging.info(f"Config saved to {CONFIG_YAML_PATH}")
        return jsonify({
            "status":      "saved",
            "org":         org,
            "token_set":   bool(token_to_save),
            "llm_provider": llm_to_save["provider"],
            "llm_key_set":  bool(llm_to_save["api_key"]),
        }), 200
    except Exception as e:
        logging.error(f"Error saving config: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ── Claude CLI (In-Pod) auth ──────────────────────────────────────────────────
# Runs the local `claude` CLI via your Claude subscription — no per-token API cost.
import threading as _threading
_claude_auth_url: str = ""          # "" = not started/in-progress, "error" = failed, else the OAuth URL
_claude_auth_lock = _threading.Lock()


def _claude_auth_bg():
    global _claude_auth_url
    from dementor_sca import claude_session
    try:
        url = claude_session.start_auth()
        _claude_auth_url = url or "error"
    except Exception:
        logging.exception("Claude auth start failed")
        _claude_auth_url = "error"


@app.route('/api/llm/claude-cli/status', methods=['GET'])
def api_claude_cli_status():
    """Auth status for the Claude CLI session (powers the badge)."""
    from dementor_sca import claude_session
    return jsonify(claude_session.status()), 200


@app.route('/api/llm/claude-cli/test', methods=['POST'])
def api_claude_cli_test():
    """Quick connectivity ping via `claude -p` (powers the Test button)."""
    from dementor_sca import claude_session
    return jsonify(claude_session.test()), 200


@app.route('/api/llm/claude-cli/auth', methods=['POST'])
def api_claude_cli_auth():
    """Start (or poll) the in-pod `claude auth login` flow.

    Returns one of:
      {status: ready}                       already authenticated
      {status: auth_starting}               login launched — poll again shortly
      {status: auth_needed, auth_url: ...}  open URL, sign in, paste the code
      {status: error, message: ...}         login failed — retry
    """
    global _claude_auth_url
    from dementor_sca import claude_session

    if claude_session.is_authenticated():
        _claude_auth_url = ""
        return jsonify({"status": "ready", "message": "Claude is authenticated. Ready to scan."}), 200

    with _claude_auth_lock:
        if _claude_auth_url and _claude_auth_url != "error":
            return jsonify({"status": "auth_needed", "auth_url": _claude_auth_url}), 200
        if _claude_auth_url == "error":
            _claude_auth_url = ""
            return jsonify({"status": "error", "message": "Claude auth failed. Try again."}), 200
        # Kick off login in the background; capturing the URL can take a few seconds.
        _claude_auth_url = ""
        _threading.Thread(target=_claude_auth_bg, daemon=True).start()
        return jsonify({"status": "auth_starting",
                        "message": "Starting Claude authentication… poll again in a few seconds."}), 200


@app.route('/api/llm/claude-cli/auth/code', methods=['POST'])
def api_claude_cli_auth_code():
    """Submit the authorization code from the OAuth page to finish login."""
    global _claude_auth_url
    from dementor_sca import claude_session
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    if not code:
        return jsonify({"ok": False, "error": "No code provided"}), 400
    ok = claude_session.submit_code(code)
    _claude_auth_url = ""
    if ok:
        return jsonify({"ok": True, "message": "Authenticated! You can now scan."}), 200
    return jsonify({"ok": False, "error": "Code rejected or session not established."}), 200


# ── Call-graph visualizer ─────────────────────────────────────────────────────

@app.route('/api/callgraph/repos', methods=['GET'])
def api_callgraph_repos():
    """List locally-cloned repos available for call-graph visualization."""
    repos = []
    if REPOSITORIES_DIR.is_dir():
        repos = sorted(p.name for p in REPOSITORIES_DIR.iterdir()
                       if p.is_dir() and not p.name.startswith('.'))
    return jsonify({"repos": repos}), 200


def _repo_from_location(loc: str) -> str:
    parts = [p for p in (loc or "").replace("\\", "/").split("/") if p]
    if "REPOSITORIES" in parts:
        i = parts.index("REPOSITORIES")
        if i + 1 < len(parts):
            return parts[i + 1]
    return ""


@app.route('/api/repo-summary', methods=['GET'])
def api_repo_summary():
    """Repo-centric overview: each repo with its finding counts, for the Repositories tab."""
    cloned = set()
    if REPOSITORIES_DIR.is_dir():
        cloned = {p.name for p in REPOSITORIES_DIR.iterdir() if p.is_dir() and not p.name.startswith(".")}

    by_repo = {}
    for e in read_vulnerability_data():
        r = _repo_from_location(e.get("file_location"))
        if not r:
            continue
        g = by_repo.setdefault(r, {"findings": 0, "reachable": 0})
        g["findings"] += 1
        if e.get("llm_confirms_vuln") or e.get("vulnerable_function_reached"):
            g["reachable"] += 1

    cfg = load_config()
    configured = (cfg.get("scan") or {}).get("repos") or []
    repos = sorted(set(cloned) | set(by_repo) | set(configured))
    out = [{
        "repo": r,
        "cloned": r in cloned,
        # "scanned" = a scan actually ran: it has findings, OR carries the post-scan marker.
        # (Being merely present on disk — e.g. a fresh upload — is NOT "scanned".)
        "scanned": (r in by_repo) or (REPOSITORIES_DIR / r / ".dementor_scanned").exists(),
        "findings": by_repo.get(r, {}).get("findings", 0),
        "reachable": by_repo.get(r, {}).get("reachable", 0),
        "is_local": (REPOSITORIES_DIR / r / ".dementor_local").exists(),
        # kept = pinned by user, or an uploaded copy (re-uploading is annoying)
        "keep": (REPOSITORIES_DIR / r / ".dementor_keep").exists()
                or (REPOSITORIES_DIR / r / ".dementor_local").exists(),
    } for r in repos]
    in_docker = bool(os.getenv("DEMENTOR_IN_DOCKER")) or os.path.exists("/.dockerenv")
    return jsonify({
        "repos": out,
        "repos_dir": str(REPOSITORIES_DIR),   # container path when in Docker
        "in_docker": in_docker,
    }), 200


@app.route('/api/usage', methods=['GET'])
def api_usage():
    """Cumulative LLM token usage + cost since the server started."""
    from dementor_sca import llm_client
    return jsonify(llm_client.get_usage()), 200


@app.route('/api/exposure', methods=['GET'])
def api_exposure():
    """Classify a repo's external exposure (internet-facing vs internal) for compliance triage.
    Query: ?repo=<name>"""
    repo = (request.args.get("repo") or "").strip()
    if not repo or "/" in repo or ".." in repo:
        return jsonify({"error": "invalid repo"}), 400
    repo_path = REPOSITORIES_DIR / repo
    try:
        from dementor_sca.exposure import classify_exposure
        result = classify_exposure(repo_path, repo_name=repo)
    except Exception as e:
        logging.exception("exposure classify failed")
        return jsonify({"error": str(e)}), 500
    result["repo"] = repo
    return jsonify(result), 200


@app.route('/api/reachability-flow', methods=['GET'])
def api_reachability_flow():
    """
    The actual reachability flow for ONE finding (library/CVE): ordered path(s) from
    the user's code to the vulnerable sink — not the whole-repo graph.
    Query: ?repo=<name>&library=<lib>
    """
    repo = (request.args.get("repo") or "").strip()
    library = (request.args.get("library") or "").strip()
    if not repo or not library:
        return jsonify({"error": "repo and library are required"}), 400

    finding = None
    for e in read_vulnerability_data():
        if e.get("library") == library and repo in (e.get("file_location", "") or ""):
            finding = e
            break
    if finding is None:
        return jsonify({"error": "finding not found"}), 404

    symbols = sorted({s for v in finding.get("vulnerabilities", [])
                      for s in (v.get("vulnerability_usage_analysis") or []) if s})
    cve_ids = sorted({c for v in finding.get("vulnerabilities", []) for c in (v.get("cve_ids") or [])})

    # Sink files come from the reachability evidence (where the lib was actually used).
    evidence = finding.get("evidence") or finding.get("reachability_evidence") or []
    seen, candidates = set(), []
    for ev in evidence:
        f = (ev.get("file") or "").strip()
        if not f or ev.get("file_type") == "infra" or f in seen:
            continue
        seen.add(f)
        # evidence 'file' is like "<repo>/<relpath>"; resolve under REPOSITORIES/.
        p = REPOSITORIES_DIR / f
        if not p.exists():
            p = REPOSITORIES_DIR / repo / f
        if p.exists():
            candidates.append(p)

    # verdict_only: fast path for the list — compute reachability WITHOUT the LLM trace
    # (tree-sitter sink check only), so the list filter/badges reflect the PRECISE verdict
    # cheaply across all findings.
    verdict_only = bool(request.args.get("verdict_only"))

    flows = []
    try:
        from dementor_sca.callgraph import gather_flow_candidates, build_reachability_paths
        from dementor_sca.reachability_scan import trace_reachability_flow_llm
        repo_root = REPOSITORIES_DIR / repo
        for cf in candidates:
            cand = gather_flow_candidates(repo_root, cf, symbols)
            if not cand:
                continue
            if verdict_only:
                # tree-sitter found a real qualified sink call → function-reachable. No LLM.
                flows.append({"paths": [[{"is_sink": True}]], "sink_symbol": cand.get("sink_symbol")})
                break
            # AI-traced exact flow (grounded in real code, validated). Falls back to the
            # static name-based path only if AI tracing is unavailable/empty.
            res = trace_reachability_flow_llm(cand)
            if not res or not res.get("paths"):
                res = build_reachability_paths(repo_root, cf, symbols)
            if res and res.get("paths"):
                flows.append(res)
    except Exception as e:
        logging.exception("reachability-flow failed")
        return jsonify({"error": str(e)}), 500

    _rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    severity = max((v.get("severity", "") or "" for v in finding.get("vulnerabilities", [])),
                   key=lambda s: _rank.get(s.lower(), 0), default="medium") or "medium"

    import re as _re

    def _extract_fixed_version(summary: str, details: str):
        """Recover the fix version from advisory prose when OSV's structured fixed
        event is missing. Finds a remediation keyword, then the FIRST version number
        within the next ~50 chars — tolerant of phrasings like 'upgrade to at least
        Requests 2.33.0' or 'releases prior to 2.32.4'."""
        text = f"{summary} {details}"
        low = text.lower()
        vpat = _re.compile(r"(\d+\.\d+(?:\.\d+)?)")
        # Explicit fix phrasings first, then affected-range upper bounds.
        for kw in ("upgrade to", "update to", "fixed in", "patched in", "resolved in",
                   "addressed in", "remediation", "prior to", "before version",
                   "earlier than", "older than", "less than"):
            idx = low.find(kw)
            if idx >= 0:
                m = vpat.search(text[idx: idx + 60])
                if m:
                    return m.group(1)
        return None

    # Per-CVE detail so a security engineer can judge the finding without leaving the row.
    vulns = [{
        "cve": (v.get("cve_ids") or [v.get("osv_id")] or ["?"])[0],
        "osv_id": v.get("osv_id"),
        "severity": v.get("severity") or "",
        "summary": v.get("summary") or "",
        "details": (v.get("details") or "")[:600],
        "fixed_in": v.get("fixed_in_branch") or _extract_fixed_version(v.get("summary") or "", v.get("details") or ""),
    } for v in finding.get("vulnerabilities", [])]

    # Attack-chain context: where untrusted input enters, and whether input is even needed.
    ev = finding.get("evidence") or finding.get("reachability_evidence") or []
    user_input = any(e.get("user_input_in_args") for e in ev)
    exploit_without_input = any(e.get("exploit_without_user_input") for e in ev)
    input_source = next((e.get("input_source") for e in ev
                         if e.get("input_source") and e.get("input_source") != "N/A"), "")

    # ── Evidence chain: declared → imported → called → reachable, each with code proof ──
    def _abs_from_evidence_file(f: str):
        for cand in (REPOSITORIES_DIR / f, REPOSITORIES_DIR / repo / f):
            if cand.exists():
                return cand
        return None

    def _snip(abs_path, line=None, term=None, before=2, after=3):
        """A few lines of real code as proof, with the relevant line marked 'hot'."""
        try:
            lines = Path(abs_path).read_text("utf-8", errors="ignore").splitlines()
        except Exception:
            return None
        idx = None
        if line and 1 <= line <= len(lines):
            idx = line - 1
        elif term:
            t = term.split(".")[-1].lower()
            for k, ln in enumerate(lines):
                if t in ln.lower():
                    idx = k
                    break
        if idx is None:
            return None
        lo, hi = max(0, idx - before), min(len(lines), idx + after + 1)
        return {"file": Path(abs_path).name,
                "lines": [{"n": lo + j + 1, "t": lines[lo + j][:200], "hot": (lo + j == idx)} for j in range(hi - lo)]}

    def _is_test_path(f: str) -> bool:
        n = (f or "").replace("\\", "/")
        base = n.split("/")[-1]
        return ("/test/" in n or "/tests/" in n
                or base.endswith(("Test.java", "Tests.java", "IT.java"))
                or base.startswith(("Test", "test_"))
                or ".test." in base or ".spec." in base)

    artifact = library.split(":")[-1]
    manifest = Path(finding.get("file_location", "") or "")
    ev_code = [e for e in ev if e.get("file") and e.get("file_type") != "infra"]
    # Prefer real (non-test) source as the "imported" proof — test code isn't production-reachable.
    ev_code.sort(key=lambda e: _is_test_path(e.get("file", "")))

    declared_proof = (_snip(manifest, term=artifact) if manifest.exists() else None)
    imported_proof = None
    imported_is_test = bool(ev_code) and _is_test_path(ev_code[0]["file"])
    if ev_code:
        ab = _abs_from_evidence_file(ev_code[0]["file"])
        if ab:
            imported_proof = _snip(ab, line=ev_code[0].get("line"))
            # Fall back to locating the import/usage by the artifact or any symbol token.
            for t in ([artifact] + [s.split(".")[-1] for s in symbols] + [s.split(".")[0] for s in symbols if "." in s]):
                if imported_proof:
                    break
                imported_proof = _snip(ab, term=t)
    called_proof = None
    if flows:
        fl = flows[0]
        ab = next((_abs_from_evidence_file(e["file"]) for e in ev_code
                   if Path(e["file"]).name == fl.get("sink_file")), None)
        if ab:
            called_proof = _snip(ab, line=fl.get("sink_line"), term=fl.get("sink_symbol"))

    # For BEHAVIORAL CVEs there's no traceable sink, so the step-3 proof should be the SPECIFIC
    # usage CODE (e.g. the waitress.serve() call) — not the aggregate AI notes (which belong on
    # the reachable step). Pick the usage that actually exercises the library.
    behavior_usage = next((e for e in ev_code if e.get("active_exploit") or e.get("apis_called")),
                          ev_code[0] if ev_code else None)
    behavior_proof = None
    if behavior_usage:
        _ab = _abs_from_evidence_file(behavior_usage.get("file", ""))
        if _ab:
            _terms = (behavior_usage.get("apis_called") or []) + [artifact]
            behavior_proof = _snip(_ab, line=behavior_usage.get("line"),
                                   term=str(_terms[0]).split(".")[-1] if _terms else None)

    # Reconcile the verdict: the PRECISE flow tracer (qualified matching) is authoritative
    # over the scan's coarse llm_confirms_vuln, which can over-match generic methods.
    #   behavioral : no specific function (usage = exposure)
    #   reachable  : function-level CVE AND a real call path/sink was found
    #   latent     : scan flagged it used, but the vulnerable function is NOT actually
    #                called → likely a false positive (e.g. generic getClass()).
    scan_said_reached = bool(finding.get("llm_confirms_vuln") or finding.get("vulnerable_function_reached"))
    function_reachable = bool(flows)
    if function_reachable:
        # call graph found a real path to a named vulnerable sink — strongest signal.
        verdict = "reachable"
    elif scan_said_reached:
        # No single named sink in the call graph, but the scan (mitigation-aware, gated)
        # confirmed reachability/exploit — e.g. BEHAVIORAL CVEs where usage == exposure
        # (waitress.serve() exposes a DoS; no specific function to trace). Respect the
        # authoritative scan verdict instead of mislabeling it "latent" (which contradicted
        # the Results tab).
        verdict = "behavioral"
    else:
        verdict = "latent"

    if verdict_only:
        return jsonify({
            "library": library, "verdict": verdict,
            "function_reachable": function_reachable,
            "reached": verdict in ("reachable", "behavioral"),
            "severity": severity,
        }), 200

    imported = bool(finding.get("is_used")) or function_reachable
    behavioral = (verdict == "behavioral") or (not symbols and scan_said_reached)
    ra = finding.get("reachability_analysis") or {}
    scan_notes = ra.get("notes") or ""
    scan_api_used = bool(ra.get("vulnerable_api_used"))
    # Proof text = the SUBSTANTIVE per-usage reasoning (what the code does + why it is/ isn't a
    # risk + any mitigation), NOT the aggregate notes — those prepend boilerplate verdict lines
    # ("active exploit confirmed", "⚠ Active exploit path confirmed") that just restate the
    # chain's status badges. The per-usage summary is the meaningful detail.
    _reason = (behavior_usage or {}).get("usage_summary", "").strip() if behavior_usage else ""
    _mit = (behavior_usage or {}).get("mitigation", "").strip() if behavior_usage else ""
    if _reason and _mit and _mit.lower() not in _reason.lower():
        _reason = f"{_reason}  Mitigation: {_mit}"
    notes_proof = {"text": _reason or scan_notes} if (_reason or scan_notes) else None

    # Step 3 — "vulnerable function/behavior". For behavioral CVEs there is no callable
    # function, so show the scan's behavioral judgment (not a misleading ✗).
    if behavioral:
        _apis = ", ".join(str(a) for a in (behavior_usage or {}).get("apis_called", [])[:4]) if behavior_usage else ""
        _loc = f"{behavior_usage['file'].split('/')[-1]}:{behavior_usage.get('line')}" if behavior_usage and behavior_usage.get("file") else ""
        called_rung = {
            "stage": "called", "label": "Vulnerable behaviour exercised",
            "status": "info",
            # Concise, location-specific detail — the full AI reasoning lives on the reachable step.
            "detail": (f"{_apis} at {_loc}" if _apis and _loc else
                       f"library exercised at {_loc}" if _loc else
                       "the library is used in a way that exercises the vulnerable behaviour"),
            "proof": behavior_proof or notes_proof,   # prefer the actual usage code over the notes blob
        }
    else:
        called_rung = {
            "stage": "called", "label": "Vulnerable function actually called",
            "status": "yes" if function_reachable else "no",
            "detail": (f"{flows[0]['sink_symbol']}() at {flows[0]['sink_file']}:{flows[0].get('sink_line')}" if function_reachable else "no real call to the vulnerable function found"),
            "proof": called_proof,
        }

    reachable_status = ("yes" if (verdict == "reachable" or (behavioral and (exploit_without_input or user_input)))
                        else ("info" if behavioral else "no"))

    # Scannable proof for the reachable step: key signals as labeled rows + a one-line summary +
    # the full analysis tucked behind a "show full analysis" toggle — instead of a wall of text.
    reachable_proof = None
    if reachable_status != "no":
        facts = []
        if exploit_without_input:
            facts.append({"label": "Trigger", "value": "Auto-triggered — no user input required"})
        elif user_input:
            facts.append({"label": "Trigger", "value": "Via user input" + (f" — {input_source}" if input_source and input_source != "N/A" else "")})
        _mit = (behavior_usage or {}).get("mitigation", "").strip() if behavior_usage else ""
        facts.append({"label": "Mitigation", "value": _mit or "None found"})
        if cve_ids:
            facts.append({"label": "CVEs", "value": ", ".join(cve_ids[:6])})
        _full = (_reason or scan_notes or "").strip()
        _summary = _full.split(". ")[0].strip()
        if _summary and not _summary.endswith("."):
            _summary += "."
        if len(_summary) > 220:
            _summary = _summary[:217] + "…"
        reachable_proof = {"summary": _summary, "facts": facts,
                           "detail": (_full if _full and len(_full) > len(_summary) + 2 else "")}

    evidence_chain = [
        {"stage": "declared", "label": "Vulnerable version declared", "status": "yes",
         "detail": f"{library} {finding.get('version_in_use') or ''} in {manifest.name}",
         "proof": declared_proof},
        {"stage": "imported", "label": "Imported / referenced in your code",
         "status": "yes" if imported else "no",
         "detail": ((imported_proof["file"] + (" (test code only)" if imported_is_test else "")) if imported_proof
                    else ("found in source" if imported else "not found in source")),
         "proof": imported_proof},
        called_rung,
        {"stage": "reachable", "label": "Reachable from your code (execution path)",
         "status": reachable_status,
         # Detail must match the status — never claim "exploitable" when it's not reachable.
         "detail": ("not reachable — the vulnerable function is not actually called" if reachable_status == "no" else
                    "exploitable via user input" if user_input else
                    "exploitable without user input (auto-triggered)" if exploit_without_input else
                    "behavioral / usage-level exposure" if behavioral else
                    "vulnerable path reached" if verdict == "reachable" else
                    "reached"),
         # Scannable structured proof (rows + summary + collapsible detail); none on a latent finding.
         "proof": reachable_proof},
    ]

    return jsonify({
        "library": library, "version": finding.get("version_in_use"),
        "cve_ids": cve_ids, "symbols": symbols, "severity": severity,
        "reached": verdict == "reachable" or verdict == "behavioral",
        "verdict": verdict,
        "function_reachable": function_reachable,
        "scan_said_reached": scan_said_reached,
        "user_input": user_input, "exploit_without_input": exploit_without_input,
        "input_source": input_source,
        "evidence_chain": evidence_chain,
        "vulns": vulns,
        "flows": flows,
    }), 200


@app.route('/api/callgraph', methods=['GET'])
def api_callgraph():
    """
    Return the call graph for a cloned repo as {nodes, edges, stats}.

    Sinks (functions calling a known-vulnerable API) are auto-derived from the
    latest scan results for that repo, so the graph highlights vulnerability paths.
    Query: ?repo=<name>
    """
    repo = (request.args.get("repo") or "").strip()
    if not repo:
        return jsonify({"error": "repo is required"}), 400
    repo_path = REPOSITORIES_DIR / repo
    if not repo_path.is_dir():
        return jsonify({"error": f"Repo '{repo}' not found in REPOSITORIES/"}), 404

    # Derive vulnerable symbols for this repo from the latest report → highlight as sinks.
    focus_symbols = set()
    try:
        for entry in read_vulnerability_data():
            if repo in (entry.get("file_location", "") or ""):
                for vuln in entry.get("vulnerabilities", []):
                    for s in (vuln.get("vulnerability_usage_analysis") or []):
                        if s:
                            focus_symbols.add(s)
    except Exception:
        pass

    paths_only = (request.args.get("paths_only", "1").strip() not in ("0", "false", "no"))
    try:
        from dementor_sca.callgraph import export_graph
        graph = export_graph(repo_path, focus_symbols=sorted(focus_symbols), paths_only=paths_only)
    except Exception as e:
        logging.exception("call-graph export failed")
        return jsonify({"error": str(e)}), 500
    graph["repo"] = repo
    graph["focus_symbols"] = sorted(focus_symbols)
    return jsonify(graph), 200


@app.route('/api/repos', methods=['GET'])
def api_list_repos():
    """
    List repos for the configured org from GitHub API.
    Query param: ?max=50 (default 100)
    Returns: { repos: ["name1", "name2", ...] }
    Requires token + org to be configured.
    """
    token = os.getenv("GITHUB_TOKEN") or (load_config().get("GITHUB_TOKEN")) or (load_config().get("github", {}).get("token")) or ""
    org   = load_config().get("org_name") or load_config().get("github", {}).get("org_name") or ""
    if not token or not org:
        return jsonify({"error": "GitHub token and org not configured. Save config first."}), 503

    max_repos = int(request.args.get("max", 100))
    repos = []
    page  = 1
    try:
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
        while True:
            url  = f"https://api.github.com/orgs/{org}/repos?per_page=100&page={page}&sort=updated&type=all"
            resp = http_requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            batch = resp.json()
            if not batch:
                break
            repos.extend(r["name"] for r in batch if r.get("name"))
            if max_repos and len(repos) >= max_repos:
                repos = repos[:max_repos]
                break
            page += 1
        return jsonify({"repos": repos, "total": len(repos)}), 200
    except http_requests.HTTPError as e:
        return jsonify({"error": f"GitHub API error: {e.response.status_code} — check your token/org"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Scan API ──────────────────────────────────────────────────────────────────

@app.route('/api/scan/start', methods=['POST'])
def api_scan_start():
    """
    Start a new scan job.
    Body: { token?, org?, mode, repos?, max_repos?, skip_reachability? }
    Returns: { job_id }

    If token/org are omitted, falls back to what's saved in config.
    """
    try:
        body = request.get_json() or {}
        cfg  = load_config()

        scan_cfg = {
            "token":             (body.get("token") or "").strip()
                                 or os.getenv("GITHUB_TOKEN")
                                 or cfg.get("GITHUB_TOKEN")
                                 or cfg.get("github", {}).get("token") or "",
            "org":               (body.get("org") or "").strip()
                                 or cfg.get("org_name")
                                 or cfg.get("github", {}).get("org_name") or "",
            "mode":              body.get("mode") or cfg.get("scan", {}).get("mode", "single"),
            "repos":             body.get("repos") or cfg.get("scan", {}).get("repos") or [],
            "max_repos":         int(body.get("max_repos") or cfg.get("scan", {}).get("max_repos") or 0),
            "skip_reachability": bool(body.get("skip_reachability",
                                      cfg.get("scan", {}).get("skip_reachability", False))),
            # Two-mode reachability: Normal (deterministic, default) vs AI (LLM-refined).
            "ai_reachability": bool(body.get("ai_reachability",
                                    cfg.get("scan", {}).get("ai_reachability", False))),
        }

        # GitHub creds are only needed to CLONE. A single/multi scan whose repos are already
        # present locally (e.g. uploaded folders/zips) needs no token/org — that's the
        # "scan local code, no GitHub" path.
        def _repo_present_locally(name: str) -> bool:
            base = (name or "").rstrip("/").split("/")[-1]
            base = base[:-4] if base.endswith(".git") else base
            return bool(base) and (REPOSITORIES_DIR / base).is_dir()

        repos = scan_cfg["repos"]
        needs_github = (scan_cfg["mode"] == "full_org") or not (
            repos and all(_repo_present_locally(r) for r in repos))
        if needs_github and (not scan_cfg["token"] or not scan_cfg["org"]):
            return jsonify({"error": "GitHub token and org are required to clone from GitHub. "
                                     "(Locally-uploaded repos scan without them.)"}), 400

        job_id = scan_runner.start_scan(scan_cfg)
        logging.info(f"Scan job {job_id} started: mode={scan_cfg['mode']} org={scan_cfg['org']}")
        return jsonify({"job_id": job_id}), 202

    except Exception as e:
        logging.error(f"Error starting scan: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/stop/<job_id>', methods=['POST'])
def api_scan_stop(job_id: str):
    """Request a hard stop of a running scan. Cooperative cancel — stops dispatching
    new work; in-flight LLM calls finish, so the job ends within a few seconds."""
    try:
        ok = scan_runner.request_cancel(job_id)
        if not ok:
            return jsonify({"error": "Job not found or not running"}), 404
        logging.info(f"Scan job {job_id} stop requested")
        return jsonify({"job_id": job_id, "status": "stopping"}), 202
    except Exception as e:
        logging.error(f"Error stopping scan {job_id}: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/status/<job_id>', methods=['GET'])
def api_scan_status(job_id: str):
    """
    SSE endpoint — streams live log lines for the given job until it finishes.
    Replays history if the client re-connects after the job has completed.
    Use EventSource in the browser: new EventSource('/api/scan/status/<id>')
    """
    job = scan_runner.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    return Response(
        stream_with_context(scan_runner.iter_logs(job_id)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route('/api/scan/jobs', methods=['GET'])
def api_scan_jobs():
    """Return a list of all scan jobs (newest first) for the Scans tab."""
    try:
        jobs = scan_runner.list_jobs()
        safe = []
        for j in jobs:
            safe.append({
                "job_id":      j["job_id"],
                "status":      j["status"],
                "started_at":  j.get("started_at"),
                "finished_at": j.get("finished_at"),
                "config":      j.get("config", {}),
                "log_lines":   j.get("log_lines", []),
            })
        return jsonify(safe)
    except Exception as e:
        logging.error(f"Error in /api/scan/jobs: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# --- Static Routes ---
TEMPLATES_DIR = REPO_ROOT / "templates"

@app.route('/')
def serve_dashboard():
    """Serves the main dashboard HTML. Sent with no-store so the browser always loads the
    current UI (the dashboard is a single self-contained HTML+JS file — stale caching here
    is what made pushed fixes 'not take effect' until a manual hard-refresh)."""
    resp = make_response(send_from_directory(TEMPLATES_DIR, 'dashboard.html'))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.route('/vulnerability_report_live_verified.json')
def serve_json():
    """Serves the live vulnerability report JSON file."""
    # Use the absolute path to ensure the file is found correctly
    return send_from_directory(VULNERABILITY_REPORT_PATH.parent, VULNERABILITY_REPORT_PATH.name)


@app.route('/api/results')
def api_results():
    """Returns the current vulnerability report with no-cache headers so the dashboard always gets fresh data."""
    data = read_vulnerability_data()
    resp = jsonify(data)
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


# Allowed user-set statuses (open, resolved, blocked, reopened; "new" is scan-only)
ALLOWED_STATUSES = frozenset({"open", "resolved", "blocked", "reopened", "false_positive", "accepted_risk"})


def _finding_key(entry: Dict) -> tuple:
    """Stable key for a finding: (library, version_in_use, file_location)."""
    return (
        entry.get("library") or "",
        entry.get("version_in_use") or "",
        entry.get("file_location") or "",
    )


@app.route('/api/results/update-status', methods=['POST'])
def api_results_update_status():
    """
    Update the status of a single finding. Persists to vulnerability_report_live_verified.json.
    Body: { "library": "...", "version_in_use": "...", "file_location": "...", "status": "open"|"resolved"|"blocked"|"reopened" }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400
        for key in ("library", "version_in_use", "file_location", "status"):
            if key not in data:
                return jsonify({"error": f"Missing field: {key}"}), 400
        status = (data.get("status") or "").strip().lower()
        if status not in ALLOWED_STATUSES:
            return jsonify({"error": f"status must be one of: {sorted(ALLOWED_STATUSES)}"}), 400

        key = (data["library"], data["version_in_use"], data["file_location"])
        report = read_vulnerability_data()
        for entry in report:
            if _finding_key(entry) == key:
                entry["status"] = status
                if status == "resolved":
                    from datetime import datetime, timezone
                    entry["resolved_at"] = datetime.now(timezone.utc).isoformat()
                else:
                    entry.pop("resolved_at", None)
                write_vulnerability_data(report)
                return jsonify({"ok": True, "status": status, "entry": entry}), 200

        return jsonify({"error": "Finding not found"}), 404
    except Exception as e:
        logging.exception("update-status error")
        return jsonify({"error": str(e)}), 500


@app.route('/api/results/delete', methods=['POST'])
def api_results_delete():
    """Delete a single finding from the report.
    Body: { library, version_in_use, file_location }"""
    try:
        data = request.get_json() or {}
        for k in ("library", "version_in_use", "file_location"):
            if k not in data:
                return jsonify({"error": f"Missing field: {k}"}), 400
        key = (data["library"], data["version_in_use"], data["file_location"])
        report = read_vulnerability_data()
        kept = [e for e in report if _finding_key(e) != key]
        if len(kept) == len(report):
            return jsonify({"error": "Finding not found"}), 404
        write_vulnerability_data(kept)
        return jsonify({"ok": True, "removed": len(report) - len(kept)}), 200
    except Exception as e:
        logging.exception("delete-finding error")
        return jsonify({"error": str(e)}), 500


@app.route('/api/repo/upload', methods=['POST'])
def api_repo_upload():
    """Upload one or more repositories from the local machine — as a **folder** or **.zip**.

    Each becomes REPOSITORIES/<name>/ (name = folder/zip name), marked with .dementor_local
    so it's treated as a local source (never re-cloned; shown 'local'; kept after scans).

    multipart/form-data, field 'files':
      - Folder upload: many files whose filename is a relative path (e.g. 'myrepo/src/app.py').
      - Zip upload: one or more '*.zip'.
    Path-traversal (zip-slip / '..') protected in both modes.
    """
    import zipfile, tempfile, shutil
    from werkzeug.utils import secure_filename

    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "No files uploaded (select a folder, or send .zip file(s))."}), 400

    uploaded, errors = [], []
    REPOSITORIES_DIR.mkdir(parents=True, exist_ok=True)

    # Split: folder-upload files carry a relative path in their filename ('repo/sub/f.py');
    # zip files are bare '*.zip'.
    folder_files = [f for f in files if "/" in (f.filename or "").replace("\\", "/")]
    zip_files    = [f for f in files if f not in folder_files]

    # ── Folder upload: rebuild the directory tree under REPOSITORIES/<top-dir>/ ──
    if folder_files:
        tops = {(f.filename or "").replace("\\", "/").split("/", 1)[0] for f in folder_files}
        for top in tops:
            repo_name = secure_filename(top) or "uploaded-repo"
            dest = REPOSITORIES_DIR / repo_name
            if dest.exists():
                errors.append(f"{repo_name}: a repo with this name already exists — delete it first")
                continue
            root = dest.resolve()
            wrote = 0
            try:
                for f in folder_files:
                    rel = (f.filename or "").replace("\\", "/")
                    if not rel.startswith(top + "/"):
                        continue
                    subpath = rel[len(top) + 1:]
                    if not subpath or subpath.endswith("/"):
                        continue
                    target = (dest / subpath).resolve()
                    if not str(target).startswith(str(root) + os.sep):
                        raise ValueError(f"unsafe path in upload: {rel}")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    f.save(str(target))
                    wrote += 1
                if wrote == 0:
                    raise ValueError("no files received")
                (dest / ".dementor_local").write_text("local upload\n", encoding="utf-8")
                uploaded.append(repo_name)
                logging.info(f"Repo uploaded (folder): {repo_name} ({wrote} files)")
            except Exception as e:
                logging.exception("folder upload error")
                errors.append(f"{top}: {e}")
                shutil.rmtree(dest, ignore_errors=True)

    # ── Zip upload ──
    for fs in zip_files:
        fname = secure_filename(fs.filename or "")
        if not fname.lower().endswith(".zip"):
            errors.append(f"{fs.filename}: only .zip uploads are supported")
            continue
        repo_name = secure_filename(fname[:-4]) or "uploaded-repo"
        dest = REPOSITORIES_DIR / repo_name
        if dest.exists():
            errors.append(f"{repo_name}: a repo with this name already exists — delete it first")
            continue

        tmpdir = Path(tempfile.mkdtemp(prefix="dm-upload-"))
        try:
            zpath = tmpdir / "upload.zip"
            fs.save(str(zpath))
            with zipfile.ZipFile(zpath) as zf:
                # Zip-slip guard: every member must resolve inside the extraction root.
                extract_root = (tmpdir / "x").resolve()
                extract_root.mkdir(parents=True, exist_ok=True)
                for member in zf.namelist():
                    target = (extract_root / member).resolve()
                    if not str(target).startswith(str(extract_root) + os.sep) and target != extract_root:
                        raise ValueError(f"unsafe path in zip: {member}")
                zf.extractall(extract_root)

            # If the zip wraps everything in a single top-level dir (e.g. GitHub's
            # 'repo-main/'), use that as the repo root so files aren't double-nested.
            entries = [p for p in extract_root.iterdir() if not p.name.startswith("__MACOSX")]
            src_root = entries[0] if len(entries) == 1 and entries[0].is_dir() else extract_root

            shutil.copytree(src_root, dest)
            (dest / ".dementor_local").write_text("local upload\n", encoding="utf-8")
            uploaded.append(repo_name)
            logging.info(f"Repo uploaded: {repo_name}")
        except zipfile.BadZipFile:
            errors.append(f"{fname}: not a valid zip file")
        except Exception as e:
            logging.exception("repo upload error")
            errors.append(f"{fname}: {e}")
            shutil.rmtree(dest, ignore_errors=True)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    status = 200 if uploaded else 400
    return jsonify({"uploaded": uploaded, "errors": errors}), status


@app.route('/api/repo/keep', methods=['POST'])
def api_repo_keep():
    """Pin/unpin a repo's cloned source so it survives the post-scan cleanup.
    Body: { repo, keep: bool }. keep=true drops a .dementor_keep marker; false removes it.
    (Local uploads are always kept regardless — deleting them would lose the source.)"""
    try:
        data = request.get_json() or {}
        repo = (data.get("repo") or "").strip()
        if not repo or "/" in repo or ".." in repo:
            return jsonify({"error": "invalid repo name"}), 400
        keep = bool(data.get("keep", True))
        repo_path = REPOSITORIES_DIR / repo
        if not repo_path.is_dir():
            return jsonify({"error": "repo not present locally (nothing to keep)"}), 404
        marker = repo_path / ".dementor_keep"
        if keep:
            marker.write_text("keep\n", encoding="utf-8")
        else:
            marker.unlink(missing_ok=True)
        return jsonify({"ok": True, "repo": repo, "keep": keep}), 200
    except Exception as e:
        logging.exception("repo keep error")
        return jsonify({"error": str(e)}), 500


@app.route('/api/repo/delete', methods=['POST'])
def api_repo_delete():
    """Remove a repo from the dashboard. Everything in REPOSITORIES/ is a COPY (a git clone
    or an uploaded copy), so deleting it never touches an original working folder.
    Body: { repo, findings_only?: bool }
      findings_only=false (default) → delete the copied source + its findings.
      findings_only=true            → keep the copy, just clear this repo's findings."""
    try:
        import shutil
        data = request.get_json() or {}
        repo = (data.get("repo") or "").strip()
        if not repo or "/" in repo or ".." in repo:
            return jsonify({"error": "invalid repo name"}), 400
        findings_only = bool(data.get("findings_only", False))

        removed_dir = False
        if not findings_only:
            repo_path = REPOSITORIES_DIR / repo
            if repo_path.is_dir():
                shutil.rmtree(repo_path, ignore_errors=True)
                removed_dir = not repo_path.exists()

        report = read_vulnerability_data()
        kept = [e for e in report if _repo_from_location(e.get("file_location")) != repo]
        dropped = len(report) - len(kept)
        if dropped:
            write_vulnerability_data(kept)
        return jsonify({"ok": True, "removed_dir": removed_dir,
                        "findings_removed": dropped, "findings_only": findings_only}), 200
    except Exception as e:
        logging.exception("delete-repo error")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    # Ensure the directory for cloned repositories exists for reachability scan
    REACH_CLONED_REPOS_PARENT.mkdir(parents=True, exist_ok=True)

    # Initialize an empty vulnerability report file if it doesn't exist
    if not VULNERABILITY_REPORT_PATH.exists():
        try:
            write_vulnerability_data([])
            logging.info(f"Created empty {VULNERABILITY_REPORT_PATH.name} as it did not exist.")
        except Exception as e:
            logging.error(f"Could not create empty {VULNERABILITY_REPORT_PATH.name}: {e}")

    # Run the Flask application.
    # IMPORTANT: the auto-reloader (default with debug=True) restarts the process on any file
    # change and KILLS in-progress scans (they run in background threads inside this process).
    # Disable the reloader by default so long scans complete; both knobs are env-configurable.
    debug = os.getenv("DEMENTOR_DEBUG", "").lower() in ("1", "true", "yes")
    use_reloader = os.getenv("DEMENTOR_RELOAD", "").lower() in ("1", "true", "yes")
    port = int(os.getenv("PORT", "5000"))   # override e.g. PORT=5050 if 5000 is taken
    app.run(host='0.0.0.0', port=port, debug=debug, use_reloader=use_reloader)