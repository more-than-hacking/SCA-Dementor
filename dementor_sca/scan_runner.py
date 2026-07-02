"""
scan_runner.py — Background scan orchestrator with live SSE log streaming.

Accepts a scan config dict, runs the full pipeline in a background thread,
and streams log lines to any listener via a queue.

Usage (from server.py):
    job_id = scan_runner.start_scan(config_dict)
    # Then SSE-stream from scan_runner.log_queue(job_id)
"""

import json
import logging
import os
import queue
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import requests as http_requests
import yaml

from dementor_sca import REPO_ROOT

# ── Paths ──────────────────────────────────────────────────────────────────────
REPOSITORIES_DIR = REPO_ROOT / "REPOSITORIES"

# All completed/failed job metadata is persisted here so it survives container restarts
_JOBS_FILE = REPO_ROOT / "scan_jobs.jsonl"

# ── Job registry ──────────────────────────────────────────────────────────────
# { job_id: { "status": "running"|"done"|"error",
#             "_write_q": Queue,         ← internal write queue (not serialised)
#             "_subscribers": [...],     ← live SSE subscriber queues (not serialised)
#             "log_lines": [str, ...],   ← persisted to disk
#             "config": {...},
#             "started_at": float, "finished_at": float } }
_JOBS: Dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()


# ── Disk persistence helpers ──────────────────────────────────────────────────

def _serialisable(job: dict) -> dict:
    """Return a JSON-safe snapshot of a job (drops queues/threads)."""
    return {
        "job_id":      job["job_id"],
        "status":      job["status"],
        "started_at":  job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "config":      job.get("config", {}),
        "log_lines":   job.get("log_lines", []),
    }


def _flush_job(job_id: str) -> None:
    """Rewrite scan_jobs.jsonl with the current in-memory state of all jobs."""
    try:
        with _JOBS_LOCK:
            snapshot = [_serialisable({**j, "job_id": jid}) for jid, j in _JOBS.items()]
        _JOBS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _JOBS_FILE.with_suffix(".tmp")
        with open(tmp, "w") as f:
            for rec in sorted(snapshot, key=lambda r: r.get("started_at") or 0):
                f.write(json.dumps(rec) + "\n")
        tmp.replace(_JOBS_FILE)
    except Exception as e:
        logging.warning(f"scan_runner: could not flush jobs to disk: {e}")


def _load_jobs_from_disk() -> None:
    """Load persisted job records into _JOBS on startup.
    Jobs that were 'running' when the process died are marked 'interrupted'.
    """
    if not _JOBS_FILE.exists():
        return
    loaded = 0
    try:
        with open(_JOBS_FILE) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                jid = rec.get("job_id")
                if not jid:
                    continue
                # Jobs that were running when the container died → mark interrupted
                if rec.get("status") == "running":
                    rec["status"] = "interrupted"
                    rec.setdefault("log_lines", []).append(
                        "⚠️  Process restarted — scan was interrupted."
                    )
                _JOBS[jid] = {
                    **rec,
                    "_write_q":    None,   # no live queue after restart
                    "_subscribers": [],
                }
                loaded += 1
        logging.info(f"scan_runner: loaded {loaded} job(s) from {_JOBS_FILE}")
    except Exception as e:
        logging.warning(f"scan_runner: could not load jobs from disk: {e}")


# Load persisted jobs when this module is first imported
_load_jobs_from_disk()


# ── Public API ────────────────────────────────────────────────────────────────

def list_jobs() -> List[dict]:
    """Return a summary of all jobs (newest first), safe to JSON-serialize."""
    with _JOBS_LOCK:
        summaries = [_serialisable({**j, "job_id": jid}) for jid, j in _JOBS.items()]
    return sorted(summaries, key=lambda j: j.get("started_at") or 0, reverse=True)


def start_scan(scan_config: dict) -> str:
    """
    Start a scan job in a background thread.
    Returns job_id immediately; SSE clients call iter_logs(job_id).

    scan_config keys:
        token          str   GitHub PAT
        org            str   GitHub org name
        mode           str   "single" | "multi" | "full_org"
        repos          list  repo names (used for single/multi)
        max_repos      int   cap for full_org (0 = no limit)
        skip_reachability bool  skip LLM phase; OSV-only
    """
    job_id = str(uuid.uuid4())[:8]
    # Internal write-queue used only by _run_scan to publish lines
    write_q: queue.Queue = queue.Queue()

    config_summary = {
        "org":               scan_config.get("org", ""),
        "mode":              scan_config.get("mode", "single"),
        "repos":             scan_config.get("repos") or [],
        "max_repos":         scan_config.get("max_repos", 0),
        "skip_reachability": scan_config.get("skip_reachability", False),
        "ai_reachability":   scan_config.get("ai_reachability", False),
    }

    with _JOBS_LOCK:
        _JOBS[job_id] = {
            "job_id":      job_id,
            "status":      "running",
            "_write_q":    write_q,          # internal; _run_scan writes here (not serialised)
            "_subscribers": [],              # live SSE subscriber queues (not serialised)
            "cancel_event": threading.Event(),  # set() by request_cancel() to stop the scan
            "log_lines":   [],              # appended by fanout thread; persisted to disk
            "config":      config_summary,
            "started_at":  time.time(),
            "finished_at": None,
            "result_path": str(REPO_ROOT / "vulnerability_report_live_verified.json"),
        }
    _flush_job(job_id)  # persist immediately so a crash still records the job as "running"

    # Fan-out thread: reads from write_q, appends to log_lines, distributes to subscribers.
    # Flushes to disk every FLUSH_EVERY lines and on final sentinel.
    FLUSH_EVERY = 10

    def _fanout():
        lines_since_flush = 0
        while True:
            try:
                item = write_q.get(timeout=1)
            except queue.Empty:
                with _JOBS_LOCK:
                    job = _JOBS.get(job_id, {})
                    if job.get("status") != "running":
                        for sq in job.get("_subscribers", []):
                            sq.put(None)
                        break
                continue

            if item is None:  # sentinel — scan finished
                with _JOBS_LOCK:
                    job = _JOBS.get(job_id, {})
                    for sq in job.get("_subscribers", []):
                        sq.put(None)
                _flush_job(job_id)   # final flush with done/error status
                break

            with _JOBS_LOCK:
                job = _JOBS.get(job_id, {})
                job.setdefault("log_lines", []).append(item)
                for sq in job.get("_subscribers", []):
                    sq.put(item)

            lines_since_flush += 1
            if lines_since_flush >= FLUSH_EVERY:
                _flush_job(job_id)
                lines_since_flush = 0

    threading.Thread(target=_fanout, daemon=True, name=f"fanout-{job_id}").start()

    thread = threading.Thread(
        target=_run_scan,
        args=(job_id, scan_config, write_q),
        daemon=True,
        name=f"scan-{job_id}",
    )
    thread.start()
    return job_id


def get_job(job_id: str) -> Optional[dict]:
    with _JOBS_LOCK:
        return _JOBS.get(job_id)


def iter_logs(job_id: str):
    """
    Generator — yields SSE-formatted log lines.

    For a FINISHED job: immediately replays all persisted log_lines then closes.
    For a RUNNING job:  replays history, then subscribes to live fan-out queue.

    Multiple simultaneous clients are supported via the fan-out mechanism.
    """
    job = get_job(job_id)
    if not job:
        yield "data: Job not found\n\n"
        return

    # --- Snapshot: grab history and register subscriber atomically -----
    with _JOBS_LOCK:
        history = list(job.get("log_lines", []))
        status  = job["status"]
        # A job is truly "live" only if it has an active write queue (i.e. started in this process).
        # Jobs loaded from disk after a restart have _write_q=None — treat them as finished.
        running = (status == "running") and (job.get("_write_q") is not None)
        if running:
            sub_q: queue.Queue = queue.Queue()
            job.setdefault("_subscribers", []).append(sub_q)

    # Replay history to this client
    for line in history:
        yield f"data: {line}\n\n"

    if not running:
        # Job finished (or was interrupted on restart) — send status and close
        yield f"data: __STATUS__:{status}\n\n"
        return

    # --- Live stream from our dedicated subscriber queue ---------------
    try:
        while True:
            try:
                item = sub_q.get(timeout=1)
                if item is None:  # sentinel — job finished
                    break
                yield f"data: {item}\n\n"
            except queue.Empty:
                yield ": keep-alive\n\n"
                # Safety: if fanout missed sentinel, check job status
                with _JOBS_LOCK:
                    if _JOBS.get(job_id, {}).get("status") != "running":
                        break
    finally:
        # Unregister subscriber (prevents memory leak)
        with _JOBS_LOCK:
            subs = _JOBS.get(job_id, {}).get("_subscribers", [])
            if sub_q in subs:
                subs.remove(sub_q)

    final_status = get_job(job_id) or {}
    yield f"data: __STATUS__:{final_status.get('status', 'unknown')}\n\n"


# ── Internal helpers ──────────────────────────────────────────────────────────

class _QueueLogger(logging.Handler):
    """Logging handler that pushes formatted records into a Queue for SSE."""

    def __init__(self, q: queue.Queue):
        super().__init__()
        self._q = q
        self.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s",
                                            datefmt="%H:%M:%S"))

    def emit(self, record):
        try:
            self._q.put_nowait(self.format(record))
        except Exception:
            pass


import re as _re

_SECRET_RE = [
    _re.compile(r"https://[^@\s/]+@"),                      # https://<token>@host  -> creds in URL
    _re.compile(r"gh[pos ur]_[A-Za-z0-9]{20,}".replace(" ", "")),  # ghp_/gho_/ghs_/ghu_/ghr_ tokens
    _re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),           # fine-grained PAT
    _re.compile(r"(?i)(token|api[_-]?key|authorization)\s*[=:]\s*\S+"),
]


def _redact(s) -> str:
    """Strip secrets (PATs, URL credentials, api keys) from a string before it is logged.
    Git clone URLs embed the token (https://<token>@github.com/...); subprocess errors echo the
    full command, so any log line could leak it without this."""
    s = str(s)
    s = _SECRET_RE[0].sub("https://***@", s)
    for rx in _SECRET_RE[1:]:
        s = rx.sub("***", s)
    return s


def _log(q: queue.Queue, level: str, msg: str, job_id: str = ""):
    """Push a plain log line to the write queue; fanout thread handles persistence.
    All messages are redacted so secrets (tokens in clone URLs / errors) never reach logs."""
    prefix = {"INFO": "ℹ", "OK": "✅", "WARN": "⚠️", "ERROR": "❌", "STEP": "🔷"}.get(level, "•")
    line = f"{prefix}  {_redact(msg)}"
    q.put_nowait(line)


def _github_headers(token: str) -> dict:
    return {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}


def _fetch_org_repos(org: str, token: str, max_repos: int, q: queue.Queue) -> List[str]:
    """Return list of repo names from the org, capped at max_repos."""
    repos = []
    page = 1
    _log(q, "STEP", f"Fetching repo list for org '{org}'...")
    while True:
        url = f"https://api.github.com/orgs/{org}/repos?per_page=100&page={page}"
        try:
            resp = http_requests.get(url, headers=_github_headers(token), timeout=30)
            resp.raise_for_status()
            data = resp.json()
            if not data:
                break
            repos.extend(r["name"] for r in data if r.get("name"))
            _log(q, "INFO", f"  Page {page}: {len(data)} repos (total so far: {len(repos)})")
            if max_repos and len(repos) >= max_repos:
                repos = repos[:max_repos]
                _log(q, "INFO", f"  max_repos={max_repos} reached — stopping pagination")
                break
            page += 1
            time.sleep(0.5)
        except Exception as e:
            _log(q, "ERROR", f"GitHub API error: {e}")
            break
    _log(q, "OK", f"Will scan {len(repos)} repo(s): {', '.join(repos)}")
    return repos


def _clone_or_update(repo_name: str, org: str, token: str, q: queue.Queue) -> Optional[Path]:
    """Clone (depth=1) or git-pull a repo into REPOSITORIES/<name>. Returns path or None.

    `repo_name` may be a bare name (uses the configured org), an "owner/repo" path (any GitHub
    owner — e.g. a public test repo like harekrishnarai/Damn-vulnerable-sca), or a full git URL."""
    import subprocess
    raw = (repo_name or "").strip()
    if raw.startswith(("http://", "https://", "git@")):
        local = raw.rstrip("/").rsplit("/", 1)[-1]
        local = local[:-4] if local.endswith(".git") else local
        clone_url = raw                                            # caller supplies any creds
    elif "/" in raw:                                               # owner/repo (any owner)
        owner_repo = raw[:-4] if raw.endswith(".git") else raw
        local = owner_repo.rsplit("/", 1)[-1]
        clone_url = f"https://{token + '@' if token else ''}github.com/{owner_repo}.git"
    else:                                                          # bare name -> configured org
        local = raw
        clone_url = f"https://{token}@github.com/{org}/{raw}.git"
    repo_path = REPOSITORIES_DIR / local

    try:
        REPOSITORIES_DIR.mkdir(parents=True, exist_ok=True)
        if (repo_path / ".git").is_dir():
            _log(q, "INFO", f"  {local}: pulling latest changes...")
            subprocess.run(["git", "pull", "--ff-only"], cwd=repo_path,
                           capture_output=True, timeout=120, check=True)
        elif repo_path.exists() and any(repo_path.iterdir()):
            # Already present locally — previously scanned (.git stripped) or a non-org public
            # repo re-scanned by bare name. REUSE the local source instead of re-cloning from the
            # org (which would 404 for non-org names AND destroy the existing copy). Re-scan
            # buttons that pass just the repo name now work.
            _log(q, "INFO", f"  {local}: using existing local copy in REPOSITORIES/ (skipping clone)")
            return repo_path
        else:
            _log(q, "INFO", f"  {local}: cloning (depth=1)...")
            subprocess.run(["git", "clone", "--depth", "1", clone_url, str(repo_path)],
                           capture_output=True, timeout=300, check=True)
        return repo_path
    except Exception as e:
        _log(q, "ERROR", f"  {local}: clone/pull failed — {e}")   # _log redacts any token
        # If a fresh clone failed but a previous local copy exists, fall back to it rather than
        # losing the ability to scan (common for non-org public repos re-scanned by bare name).
        if repo_path.exists() and any(repo_path.iterdir()):
            _log(q, "WARN", f"  {local}: clone failed — falling back to existing local copy")
            return repo_path
        return None


def _remove_git_dir(repo_path: Path, q: queue.Queue):
    """Remove only the .git directory to save space; keep all source files for reachability scan."""
    git_dir = repo_path / ".git"
    if git_dir.exists():
        shutil.rmtree(git_dir, ignore_errors=True)
        _log(q, "INFO", f"  {repo_path.name}: .git directory removed (source files kept for reachability scan)")


def _run_scan(job_id: str, cfg: dict, q: queue.Queue):
    """Main scan worker — runs in a background thread."""

    # Local wrapper so every log line is also persisted in the job registry
    def log(level: str, msg: str):
        _log(q, level, msg, job_id=job_id)

    def cancelled() -> bool:
        return _is_cancelled(job_id)

    def _stop_if_cancelled() -> bool:
        if cancelled():
            log("WARN", "Scan stopped by user.")
            _finish(job_id, q, "stopped")
            return True
        return False

    try:
        token: str = cfg.get("token", "")
        org: str = cfg.get("org", "")
        mode: str = cfg.get("mode", "single")
        selected_repos: List[str] = cfg.get("repos") or []
        max_repos: int = int(cfg.get("max_repos") or 0)
        skip_reachability: bool = bool(cfg.get("skip_reachability", False))
        # Two-mode reachability: Normal (deterministic, no key) vs AI (LLM-refined).
        # Default Normal so the tool works without a key; AI is explicit opt-in.
        ai_refine: bool = bool(cfg.get("ai_reachability", False))

        # ── Validate ─────────────────────────────────────────────────────────
        # Token/org are only needed to CLONE from GitHub. If every requested repo is already
        # present locally (uploaded folder/zip, or a prior clone), scan without them.
        def _repo_present_locally(name: str) -> bool:
            base = (name or "").rstrip("/").split("/")[-1]
            base = base[:-4] if base.endswith(".git") else base
            return bool(base) and (REPOSITORIES_DIR / base).is_dir()

        needs_github = (mode == "full_org") or not (
            selected_repos and all(_repo_present_locally(r) for r in selected_repos))
        if needs_github and (not token or not org):
            log("ERROR", "GitHub token and org are required to clone from GitHub "
                         "(locally-uploaded repos scan without them).")
            _finish(job_id, q, "error")
            return

        reach_mode = "detection-only" if skip_reachability else ("AI" if ai_refine else "Normal (deterministic)")
        log("STEP", f"Scan started — mode={mode}, org={org}, reachability={reach_mode}")

        # ── Step 1: Resolve which repos to scan ──────────────────────────────
        log("STEP", "Step 1/4 — Resolving repositories")
        if mode == "full_org":
            repos_to_scan = _fetch_org_repos(org, token, max_repos, q)
        elif mode == "multi":
            repos_to_scan = selected_repos
            log("OK", f"Multi-repo mode — {len(repos_to_scan)} repo(s): {', '.join(repos_to_scan)}")
        else:  # single
            if not selected_repos:
                log("ERROR", "Single mode: no repo specified.")
                _finish(job_id, q, "error")
                return
            repos_to_scan = [selected_repos[0]]
            log("OK", f"Single repo mode — scanning: {repos_to_scan[0]}")

        if not repos_to_scan:
            log("ERROR", "No repositories to scan.")
            _finish(job_id, q, "error")
            return

        # ── Step 2: Clone / update repos ─────────────────────────────────────
        log("STEP", f"Step 2/4 — Cloning/updating {len(repos_to_scan)} repo(s)")
        cloned = []
        cloned_paths = []
        for rname in repos_to_scan:
            path = _clone_or_update(rname, org, token, q)
            if path and path.exists():
                _remove_git_dir(path, q)
                cloned.append(rname)
                cloned_paths.append(path)
            else:
                log("WARN", f"  Skipping {rname} (clone failed)")

        if not cloned:
            log("ERROR", "All repos failed to clone or had no manifests. Aborting.")
            _finish(job_id, q, "error")
            return

        log("OK", f"Cloned/updated: {', '.join(cloned)}")
        if _stop_if_cancelled():
            return

        # ── Step 3: Dependency parsing ────────────────────────────────────────
        log("STEP", "Step 3/4 — Parsing dependency manifests")
        os.environ["DEPENDENCY_SCAN_ROOT"] = str(REPOSITORIES_DIR)
        from dementor_sca.dependency_parser import main as parser_main
        parser_main()
        dep_path = REPO_ROOT / "dependency_results.json"
        if dep_path.exists():
            with open(dep_path) as f:
                deps = json.load(f)
            log("OK", f"Parsed {len(deps)} dependencies across all repos")
        else:
            log("ERROR", "dependency_results.json not produced. Aborting.")
            _finish(job_id, q, "error")
            return

        # ── Step 4: OSV vulnerability check ──────────────────────────────────
        log("STEP", "Step 4/4 — OSV vulnerability check")
        from dementor_sca.pipeline_zero_fp import run_phase2_osv_check, extract_vulnerable_symbols_from_osv
        potential = run_phase2_osv_check(deps)
        log("OK", f"OSV found {len(potential)} library/libraries with known CVEs")
        if _stop_if_cancelled():
            return

        # Symbols + safest-upgrade recommendation are computed in run_phase2_osv_check
        # (where the full OSV 'affected'/fixed-range data is available).

        if skip_reachability:
            log("INFO", "Reachability skipped (OSV-only mode). Writing report.")
            for entry in potential:
                entry["is_used"] = None
                entry["llm_confirms_vuln"] = False
                entry["reachability_analysis"] = {
                    "declared": True, "imported": None,
                    "vulnerable_api_used": None,
                    "notes": "Reachability skipped — OSV-only scan.",
                }
            report = potential
        else:
            # ── Step 5 (optional): Reachability scan ─────────────────────────
            log("STEP", f"Step 5/5 — Reachability scan ({'AI' if ai_refine else 'Normal / deterministic — no AI'})")
            from dementor_sca.pipeline_zero_fp import run_phase3_reachability, run_phase4_llm_gate
            from dementor_sca import llm_client
            _usage_before = llm_client.get_usage()
            with_reach = run_phase3_reachability(potential, token, org, should_cancel=cancelled, ai_refine=ai_refine)
            if _stop_if_cancelled():
                return
            log("OK", f"{len(with_reach)} library/libraries reached in source code")
            if ai_refine:
                confirmed = run_phase4_llm_gate(with_reach, require_llm_yes=True)
                log("OK", f"{len(confirmed)} active exploit(s) confirmed by LLM")
            # Token / cost accounting for this scan (delta over the reachability phase).
            # Only meaningful in AI mode — Normal mode makes zero LLM calls.
            if ai_refine:
                _u = llm_client.get_usage()
                _tok = {k: _u.get(k, 0) - _usage_before.get(k, 0) for k in _u}
                with _JOBS_LOCK:
                    if job_id in _JOBS:
                        _JOBS[job_id]["token_usage"] = _tok
                log("INFO", f"AI usage: {_tok['calls']} calls · {_tok['input_tokens']:,} in + "
                            f"{_tok['output_tokens']:,} out tokens (+{_tok['cache_read_tokens']:,} cached) · "
                            f"~${_tok['cost_usd']:.4f}")
            else:
                log("INFO", "Normal mode — deterministic reachability, no AI calls (cost $0).")

            # Merge reachability results back into potential for full report
            reach_map = {(e["library"], e.get("file_location", "")): e for e in with_reach}
            for entry in potential:
                key = (entry["library"], entry.get("file_location", ""))
                if key in reach_map:
                    re = reach_map[key]
                    entry["is_used"] = re.get("is_used", True)
                    entry["llm_confirms_vuln"] = re.get("llm_confirms_vuln", False)
                    entry["evidence"] = re.get("reachability_evidence", [])
                    entry["reachability_analysis"] = re.get("reachability_analysis", {})
                else:
                    entry["is_used"] = False
                    entry["llm_confirms_vuln"] = False
                    entry["evidence"] = []
                    entry["reachability_analysis"] = {
                        "declared": True, "imported": False,
                        "vulnerable_api_used": False,
                        "notes": "Library not found in source code.",
                    }
            report = potential

        # ── Merge with previous state (new / open / resolved) ──────────────────
        from dementor_sca.scan_state import merge_with_previous
        report_path = REPO_ROOT / "vulnerability_report_live_verified.json"
        report = merge_with_previous(report, report_path)

        # ── Write report ──────────────────────────────────────────────────────
        # Atomic write: temp file + os.replace() so an interrupted/overlapping scan can never
        # leave a half-written (corrupt) report on disk.
        _tmp_report = report_path.with_suffix(report_path.suffix + ".tmp")
        with open(_tmp_report, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        os.replace(_tmp_report, report_path)
        new_open = sum(1 for e in report if e.get("status") in ("new", "open"))
        resolved_count = sum(1 for e in report if e.get("status") == "resolved")
        log("OK", f"Report written → {report_path.name}  ({new_open} open/new, {resolved_count} resolved)")

        # ── Free disk: delete cloned source unless the repo is pinned "Keep" ─────
        # Findings stay in the report; a re-scan re-clones. Uploaded repos and any
        # repo the user pinned carry a .dementor_keep marker and are never deleted.
        freed = []
        for p in cloned_paths:
            try:
                if p.is_dir() and not _repo_is_kept(p):
                    shutil.rmtree(p, ignore_errors=True)
                    if not p.exists():
                        freed.append(p.name)
                elif p.is_dir():
                    # Kept repo (upload/pinned) — mark it as actually scanned so the UI shows
                    # "Scanned" only after a real scan (not just because it's present on disk).
                    try:
                        (p / ".dementor_scanned").write_text("", encoding="utf-8")
                    except Exception:
                        pass
            except Exception as e:
                log("WARN", f"  Could not free {p.name}: {e}")
        if freed:
            log("INFO", f"Freed cloned source (not kept): {', '.join(freed)}. Findings retained; re-scan re-clones. Pin 'Keep' to retain.")

        log("OK", "Scan complete. Refresh the Results tab to see findings.")
        _finish(job_id, q, "done")

    except Exception as exc:
        logging.exception(f"[scan-{job_id}] Unhandled error")
        log("ERROR", f"Unhandled error: {type(exc).__name__}: {exc}")
        _finish(job_id, q, "error")


def _is_cancelled(job_id: str) -> bool:
    """True if a stop has been requested for this job."""
    with _JOBS_LOCK:
        ev = _JOBS.get(job_id, {}).get("cancel_event")
    return bool(ev and ev.is_set())


def request_cancel(job_id: str) -> bool:
    """Request a running scan to stop. Returns False if the job is unknown or already finished.

    Cooperative cancellation: the scan worker checks the flag at phase boundaries and the
    reachability phase stops dispatching new LLM work. Already-in-flight LLM calls finish
    (Python threads can't be force-killed safely), so a stop takes effect within a few seconds.
    """
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job or job.get("status") != "running":
            return False
        ev = job.get("cancel_event")
    if ev:
        ev.set()
    return True


def _repo_is_kept(repo_path: Path) -> bool:
    """True if a repo's cloned source should be retained after a scan.

    Kept when the user pinned it (.dementor_keep) or it's an uploaded copy (.dementor_local —
    re-uploading is annoying, so uploads aren't auto-freed like git clones)."""
    return (repo_path / ".dementor_keep").exists() or (repo_path / ".dementor_local").exists()


def _finish(job_id: str, q: queue.Queue, status: str):
    with _JOBS_LOCK:
        if job_id in _JOBS:
            _JOBS[job_id]["status"] = status
            _JOBS[job_id]["finished_at"] = time.time()
    # fanout thread will do the final flush after draining the sentinel
    q.put(None)  # sentinel — tells fanout + iter_logs to stop
