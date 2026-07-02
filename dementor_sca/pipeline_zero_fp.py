#!/usr/bin/env python3
"""
Zero False Positive SCA Pipeline.

Only reports a vulnerability when ALL are true:
  1. Exact resolved version (lockfile-first)
  2. OSV confirms package+version is affected
  3. Reachability: library is used in source code
  4. Ollama confirms: code snippet could trigger this CVE

Orchestrates: resolution -> OSV -> reachability -> Ollama -> report.
"""

import json
import logging
import os
import re
from pathlib import Path

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
LOG = logging.getLogger(__name__)

# --- Vulnerable symbol extraction (for prioritization: vulnerable code path vs support-only) ---
# Generic/prose tokens that are NOT vulnerable code symbols. Lower-cased, matched
# against a candidate's last path segment. Kept deliberately broad — false sinks
# (e.g. "main", "Apache") pollute both reachability verdicts and the call graph.
_SYMBOL_DENYLIST = {
    # prose / English
    "the", "this", "that", "with", "via", "when", "which", "from", "into", "and", "or", "for",
    "use", "used", "using", "call", "calls", "code", "data", "input", "output", "user", "users",
    "error", "value", "values", "version", "versions", "vulnerable", "vulnerability", "affected",
    "security", "issue", "issues", "attack", "attacker", "remote", "allows", "allow", "may", "can",
    "could", "would", "should", "function", "functions", "method", "methods", "class", "classes",
    "object", "objects", "field", "fields", "parameter", "parameters", "argument", "arguments",
    "request", "requests", "response", "server", "client", "default", "example", "note", "see",
    "fixed", "patch", "patched", "release", "released", "update", "updated", "prior", "before",
    "after", "above", "below", "type", "types", "name", "names", "file", "files", "path", "paths",
    "main", "test", "tests", "config", "application", "applications", "library", "module", "package",
    # severity
    "low", "medium", "high", "critical", "moderate", "none",
    # common vendors / products mentioned in advisories
    "apache", "spring", "google", "oracle", "microsoft", "eclipse", "codehaus", "connect2id",
    "github", "jenkins", "tomcat", "netty", "async", "json", "xml", "http", "https", "url", "uri",
    # very common stdlib type names that show up in prose, not as the sink
    "string", "integer", "boolean", "biginteger", "charsequence", "list", "map", "set", "array",
    "collection", "exception", "runtime", "thread", "stream", "buffer",
}

# Over-generic verbs rejected only as BARE symbols (they match unrelated/framework code —
# e.g. CVE symbol "verify" from "sslmode=verify-full" matching Mockito.verify() everywhere).
# A QUALIFIED symbol like "RequestMappingHandlerAdapter.handle" is still kept — the
# call-graph's qualified matcher resolves it precisely.
_GENERIC_BARE_VERBS = {
    "verify", "validate",   # match Mockito.verify()/validation frameworks; never a bare sink
}

# Last-segment suffixes that mean "this dotted token is a domain or filename, not code".
_SUFFIX_DENYLIST = {
    "com", "org", "net", "io", "gov", "edu", "co", "dev", "info",   # TLDs / domains
    "py", "java", "js", "ts", "go", "rb", "rs", "php", "c", "cpp", "h",  # source files
    "txt", "html", "htm", "xml", "json", "md", "yaml", "yml", "cfg", "ini", "sh", "log",
}

# Real-looking identifier: camelCase, snake_case, or a clearly-cased word.
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _looks_like_code_identifier(sym: str) -> bool:
    if not _IDENT_RE.match(sym):
        return False
    # mixedCase, snake_case, or PascalCase carry signal; a plain lowercase word usually doesn't.
    return ("_" in sym) or (sym != sym.lower() and sym != sym.upper()) or len(sym) >= 6


def extract_vulnerable_symbols_from_osv(vuln: dict) -> list:
    """
    Extract the vulnerable function/class/method names from OSV vuln data, ranked by
    signal and filtered for noise. Used by reachability (grep for the vulnerable code
    path, not just the import) and by the call-graph visualizer (which functions are
    sinks). Prefers qualified names (`Class.method`) and call-syntax over prose words;
    drops generic/vendor/English tokens that previously produced false sinks.
    """
    scores: dict[str, int] = {}

    def add(sym: str, score: int):
        sym = (sym or "").strip().strip(".")
        if not (1 < len(sym) < 120):
            return
        parts = sym.split(".")
        last = parts[-1].lower()
        if last in _SYMBOL_DENYLIST or sym.lower() in _SYMBOL_DENYLIST:
            return
        if "." in sym:
            # Reject domains/filenames and abbreviations like "i.e" / "e.g".
            if last in _SUFFIX_DENYLIST or any(len(p) <= 1 for p in parts):
                return
        else:
            # Bare token: must look like a real identifier, clear a min score, and not be
            # an over-generic verb (qualified forms are kept; only bare ones are dropped).
            if not _looks_like_code_identifier(sym) or score < 3 or last in _GENERIC_BARE_VERBS:
                return
        scores[sym] = max(scores.get(sym, 0), score)

    # 1) Structured affected-symbol lists, when present (highest signal).
    for key in ("database_specific", "ecosystem_specific"):
        spec = vuln.get(key)
        if isinstance(spec, dict):
            for name in ("affected_functions", "symbols", "affected_symbols", "functions", "imports"):
                val = spec.get(name)
                for s in (val if isinstance(val, list) else [val]):
                    if isinstance(s, str):
                        add(s, 10)
                    elif isinstance(s, dict):  # OSV import objects {path, symbols:[...]}
                        for sub in s.get("symbols", []) or []:
                            add(sub, 10)

    # Strip EMBEDDED CODE BLOCKS (PoC / unit tests / patch snippets) before mining symbols.
    # Advisories often paste a full exploit test, whose local variables/imports (e.g.
    # `numberText.length`, `factory.createParser`, `System.out.println`) are NOT the library's
    # vulnerable API — matching those produced false reachability (any Java `.length()` matched).
    def _strip_code_blocks(t: str) -> str:
        t = re.sub(r"```.*?```", " ", t, flags=re.S)   # ```fenced``` code
        t = re.sub(r"~~~.*?~~~", " ", t, flags=re.S)
        return t

    combined = " ".join(_strip_code_blocks(str(vuln.get(k) or "")) for k in ("details", "summary"))

    # 2) Backticked code — `Class.method`, `readObject()`, `deserialize`.
    for m in re.finditer(r"`([A-Za-z_][A-Za-z0-9_.]*)\s*(\(?)`?", combined):
        sym, paren = m.group(1), m.group(2)
        add(sym, 6 if "." in sym else (5 if paren else 4))

    # 3) Qualified names in prose: Class.method / pkg.func.
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_.]*)\b", combined):
        add(m.group(1), 5)

    # 4) Call syntax in prose: foo(), readObject().
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)", combined):
        add(m.group(1), 3)

    # 5) "the function/method X", "calls to X", "use of X".
    for pat in (
        r"\b(?:function|method|api|call to|calls to|use of|invoking)\s+`?([A-Za-z_][A-Za-z0-9_.]*)`?",
    ):
        for m in re.finditer(pat, combined, re.IGNORECASE):
            add(m.group(1), 4)

    # 6) Reversed noun form: "X function/method/loader/class" (name BEFORE the noun) — common in
    # advisory prose, e.g. "the load_all functions", "the full_load method", "the FullLoader loader".
    # Strict: only accept code-shaped names (underscore or mixedCase) so plain English words before
    # these nouns ("the affected function", "a helper method") are NOT mistaken for symbols.
    for m in re.finditer(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s+(?:function|method|loader|constructor|deserializer|parser|routine|api|class)e?s?\b",
        combined, re.IGNORECASE,
    ):
        w = m.group(1)
        if "_" in w or w != w.lower():   # snake_case or CamelCase only — reject plain-lowercase English
            add(w, 4)

    if not scores:
        return []

    # Prefer a qualified symbol over its bare suffix (keep Class.method, drop method).
    qualified = {s for s in scores if "." in s}
    qual_suffixes = {s.split(".")[-1] for s in qualified}
    final = [s for s in scores if "." in s or s not in qual_suffixes]

    # Rank by signal, then alphabetically for determinism; cap to keep prompts/graph clean.
    final.sort(key=lambda s: (-scores[s], s))
    return final[:12]


# --- Config (will be loaded from config/zero_fp.yaml + org) ---
def load_zero_fp_config():
    from dementor_sca import REPO_ROOT
    config_path = REPO_ROOT / "config" / "zero_fp.yaml"
    if not config_path.exists():
        return {"zero_fp": {"enabled": True, "require_lockfile": True, "llm_confirm_gate": True}}
    import yaml
    with open(config_path, "r") as f:
        return yaml.safe_load(f) or {}


def run_phase1_resolved_dependencies() -> list:
    """
    Phase 1: Produce dependencies with EXACT resolved versions only.
    Prefer lockfiles; if no lockfile, skip or run package manager (TBD).
    For now, delegates to existing Dependency_Parser but could later
    switch to resolution/ module.
    When SKIP_PHASE1_USE_EXISTING=1 (e.g. from scan_single_repo --zero-fp), skip parser and use existing file.
    """
    from dementor_sca import REPO_ROOT
    dep_path = REPO_ROOT / "dependency_results.json"
    if os.getenv("SKIP_PHASE1_USE_EXISTING"):
        LOG.info("Phase 1: Using existing dependency_results.json (skip parser)")
    else:
        from dementor_sca.dependency_parser import main as parser_main
        parser_main()
    if not dep_path.exists():
        LOG.warning("dependency_results.json not found after Phase 1")
        return []
    with open(dep_path, "r") as f:
        deps = json.load(f)
    # Optional: filter to only entries that look resolved (no range symbols)
    # For now return all; Phase 2 can skip invalid versions
    # (Transitive expansion happens in run_phase2_osv_check — the single chokepoint all
    #  scan paths go through, including scan_runner which calls Phase 2 directly.)
    return deps


def run_phase2_osv_check(deps: list) -> list:
    """
    Phase 2: Query OSV for each (name, version, ecosystem).
    Return list of potential vulns: each item has library, version, file_location,
    ecosystem, vulnerabilities (list of osv_id, cve_ids, details, etc.).
    """
    from dementor_sca.sca_osv import (
        normalize_ecosystem,
        normalize_package_name,
        fetch_vulns_for_chunk,
        fetch_vuln_details,
        extract_severity,
        safest_available_upgrade,
    )
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from tqdm import tqdm

    # Phase 1b: expand direct deps with their transitive graph from adjacent lockfiles.
    # Most real-world CVEs live in transitive deps; without this they are invisible.
    # Done here (not in Phase 1) so every caller — including scan_runner, which calls
    # Phase 2 directly — benefits. Pure-Python, offline, idempotent, graceful (no lockfile
    # → deps unchanged). Tags each dep dep_type=direct|transitive.
    try:
        from dementor_sca.transitive_resolver import resolve_transitive_deps
        deps = resolve_transitive_deps(deps)
    except Exception as e:
        LOG.warning("Transitive resolution skipped: %s", e)

    MAX_QUERIES_PER_BATCH = 1000
    MAX_WORKERS = 30  # Parallel OSV batch + detail fetches

    queries, query_map = [], {}
    for lib in deps:
        eco = normalize_ecosystem(lib.get("ecosystem", ""))
        name_raw, ver = lib.get("library"), lib.get("version")
        if not (name_raw and ver and eco):
            continue
        # OSV/PyPI expects normalized (lowercase) names — otherwise e.g. "PyYAML" silently
        # returns no vulns. Query with the normalized name; keep the original for display.
        name = normalize_package_name(name_raw, eco)
        q = {"version": ver, "package": {"name": name, "ecosystem": eco}}
        queries.append(q)
        query_map[(name, ver, eco)] = lib

    vuln_map, all_ids = {}, set()
    chunks = [queries[i : i + MAX_QUERIES_PER_BATCH] for i in range(0, len(queries), MAX_QUERIES_PER_BATCH)]
    with ThreadPoolExecutor(MAX_WORKERS) as ex:
        fut_to_chunk = {ex.submit(fetch_vulns_for_chunk, c): c for c in chunks}
        for fut in tqdm(as_completed(fut_to_chunk), total=len(fut_to_chunk), desc="OSV batch"):
            chunk = fut_to_chunk[fut]
            result = fut.result()
            for i, res in enumerate(result.get("results", [])):
                if "vulns" not in res:
                    continue
                if i >= len(chunk):
                    continue
                q = chunk[i]
                k = (q["package"]["name"], q["version"], q["package"]["ecosystem"])
                vuln_map[k] = [v["id"] for v in res["vulns"]]
                all_ids.update(v["id"] for v in res["vulns"])

    details_map = {}
    with ThreadPoolExecutor(MAX_WORKERS) as ex:
        futs = {ex.submit(fetch_vuln_details, oid): oid for oid in all_ids}
        for fut in tqdm(as_completed(futs), total=len(futs), desc="OSV details"):
            res = fut.result()
            oid = futs[fut]
            details_map[oid] = res

    potential = []
    for k, ids in vuln_map.items():
        lib = query_map[k]
        name = lib["library"]          # original name, for display
        name_norm = k[0]               # normalized name used in the OSV query
        relevant = [
            details_map[i] for i in ids
            if not details_map.get(i, {}).get("error")
            and any(
                a.get("package", {}).get("name", "").lower() == name_norm.lower()
                for a in details_map[i].get("affected", [])
            )
        ]
        if not relevant:
            continue
        entry = {
            "library": name,
            "version_in_use": lib["version"],
            "ecosystem": normalize_ecosystem(lib.get("ecosystem", "")),
            "file_location": lib.get("file", ""),
            "dep_type": lib.get("dep_type", "direct"),
            "lockfile": lib.get("lockfile", ""),
            "vulnerabilities": [
                {
                    "osv_id": v.get("id"),
                    "cve_ids": [c for c in v.get("aliases", []) if "CVE" in c],
                    "severity": extract_severity(v),
                    "details": v.get("details"),
                    "summary": v.get("summary"),
                    "published": v.get("published"),
                    "modified": v.get("modified"),
                    "vulnerability_usage_analysis": extract_vulnerable_symbols_from_osv(v),
                }
                for v in relevant
            ],
        }
        # Safest available upgrade: a REAL released version that fixes all matched CVEs
        # (OSV fix target snapped to an actually-available version on the registry).
        try:
            rec = safest_available_upgrade(lib["version"], relevant, name_norm,
                                           entry["ecosystem"])
            if rec:
                entry["upgrade_recommendation"] = rec
        except Exception:
            pass
        potential.append(entry)

    # Layer 2 — threat-intel enrichment (EPSS exploit-probability + CISA KEV actively-exploited).
    # Ranks urgency of the real findings; resilient (no key, never blocks a scan).
    try:
        from dementor_sca.threat_intel import enrich_findings
        potential = enrich_findings(potential)
    except Exception as e:
        LOG.warning("Threat-intel (EPSS/KEV) enrichment skipped: %s", e)
    return potential


def _reachability_for_entry(entry: dict, github_token: str, org_name: str, ai_refine: bool = True):
    """Run the reachability scan for one OSV-flagged library entry.

    ai_refine=False runs deterministic (no-AI) reachability. Returns the enriched entry
    if the library is used in code, else None. Pure per-entry work — safe to run concurrently.
    """
    from dementor_sca.reachability_scan import scan_for_reachability
    from dementor_sca import REPO_ROOT

    file_loc = entry.get("file_location", "")
    parts = [p for p in file_loc.replace("\\", "/").strip("/").split("/") if p]
    # Find REPOSITORIES in path; repo_name is next segment, rest is path_in_repo
    try:
        idx = next(i for i, p in enumerate(parts) if p == "REPOSITORIES")
        if idx + 1 < len(parts):
            github_repo_name = parts[idx + 1]
            path_in_repo = "/".join(parts[idx + 2:]) if idx + 2 < len(parts) else ""
        else:
            github_repo_name = "unknown"
            path_in_repo = ""
    except StopIteration:
        github_repo_name = parts[0] if parts else "unknown"
        path_in_repo = "/".join(parts[1:]) if len(parts) > 1 else ""
    if not path_in_repo:
        path_in_repo = parts[-1] if parts else ""
    local_repo = REPO_ROOT / "REPOSITORIES" / github_repo_name
    if local_repo.is_dir():
        file_location_in_cloned_repo = str(local_repo / path_in_repo)
        local_repo_path = str(local_repo)
    else:
        file_location_in_cloned_repo = str(REPO_ROOT / "SCA_CLONED_REPOS" / github_repo_name / path_in_repo)
        local_repo_path = None
    lib_entry = {
        "library": entry["library"],
        "version_in_use": entry.get("version_in_use"),
        "ecosystem": entry.get("ecosystem", ""),   # scope reachability to this dep's own language
        "file_location": file_loc,
        "file_location_in_cloned_repo": file_location_in_cloned_repo,
        "vulnerabilities": entry.get("vulnerabilities", []),
    }
    try:
        result = scan_for_reachability(
            github_token=github_token,
            org_name=org_name,
            library_entry_data=lib_entry,
            github_repo_name=github_repo_name,
            local_repo_path=local_repo_path,
            ai_refine=ai_refine,
        )
    except Exception as e:
        LOG.warning("Reachability failed for %s: %s", entry.get("library"), e)
        return None
    if not result.get("is_used"):
        LOG.info("Dropping %s: not used in code (reachability)", entry.get("library"))
        return None
    # Propagate the FULL verdict — not just evidence + llm_confirms_vuln. Dropping
    # is_used / reachability_analysis left the dashboard rendering an empty analysis
    # (all "No") while llm_confirms_vuln separately drove "Active exploit: Yes" — a
    # self-contradicting panel. Carry the whole reconciled analysis through.
    entry["is_used"] = result.get("is_used", True)
    entry["reachability_evidence"] = result.get("evidence", [])
    entry["llm_confirms_vuln"] = result.get("llm_confirms_vuln", False)
    entry["vulnerable_function_reached"] = result.get("vulnerable_function_reached", False)
    entry["reachability_analysis"] = result.get("reachability_analysis", {})
    return entry


def run_phase3_reachability(potential_vulns: list, github_token: str, org_name: str,
                            should_cancel=None, ai_refine: bool = True) -> list:
    """
    Phase 3: For each potential vuln, run reachability scan (concurrently).
    Drop entries where library is not used in source; otherwise attach snippets.

    Libraries are scanned in parallel — each call is dominated by I/O (clone/grep)
    and the LLM subprocess wait, so threads give a near-linear speedup. The pool is
    deliberately small (REACHABILITY_WORKERS, default 4) because each `claude -p`
    spawns a heavy process; raise it for API-key providers, lower it on small hosts.

    should_cancel: optional zero-arg callable. When it returns True the phase stops
    dispatching new work and cancels pending entries — in-flight LLM calls still
    finish (threads can't be force-killed), so a stop lands within a few seconds.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _stop() -> bool:
        return bool(should_cancel and should_cancel())

    limit = int(os.getenv("ZERO_FP_LIMIT", "0"))  # 0 = no limit; set for quick test
    to_process = potential_vulns[:limit] if limit else potential_vulns
    if limit:
        LOG.info("ZERO_FP_LIMIT=%s: processing only first %s potential vulns (quick run)", limit, len(to_process))

    workers = max(1, int(os.getenv("REACHABILITY_WORKERS", "4")))
    workers = min(workers, len(to_process)) or 1
    LOG.info("Reachability: scanning %s OSV-flagged librar(ies) with %s worker(s)", len(to_process), workers)

    if workers == 1:
        out = []
        for entry in to_process:
            if _stop():
                LOG.info("Reachability cancelled by user — stopping.")
                break
            if (e := _reachability_for_entry(entry, github_token, org_name, ai_refine=ai_refine)):
                out.append(e)
        return out

    with_reach = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_reachability_for_entry, entry, github_token, org_name, ai_refine): entry for entry in to_process}
        for fut in as_completed(futures):
            if _stop():
                LOG.info("Reachability cancelled by user — cancelling %s pending entr(ies).",
                         sum(1 for f in futures if f.cancel()))
                break
            try:
                enriched = fut.result()
            except Exception as e:  # defensive — _reachability_for_entry already guards
                LOG.warning("Reachability worker error for %s: %s", futures[fut].get("library"), e)
                continue
            if enriched is not None:
                with_reach.append(enriched)
    return with_reach


def run_phase4_llm_gate(with_reach: list, require_llm_yes: bool) -> list:
    """
    Phase 4: If require_llm_yes, drop entries where llm_confirms_vuln is False.
    (Reachability scan already calls the LLM per snippet; we just filter by result.)
    """
    if not require_llm_yes:
        return with_reach
    confirmed = [e for e in with_reach if e.get("llm_confirms_vuln")]
    for e in with_reach:
        if not e.get("llm_confirms_vuln"):
            LOG.info("Dropping %s: LLM did not confirm CVE trigger", e.get("library"))
    return confirmed


def main():
    """Run full 0-FP pipeline and write vulnerability_report_confirmed.json."""
    import yaml
    config = load_zero_fp_config()
    zfp = config.get("zero_fp", {})
    if not zfp.get("enabled", True):
        LOG.info("Zero FP mode disabled; exiting.")
        return

    from dementor_sca import REPO_ROOT
    skip_reach = zfp.get("skip_reachability", False)
    github_token = None
    org_name = None
    if not skip_reach:
        org_config_path = REPO_ROOT / "config" / "org_config.yaml"
        if org_config_path.exists():
            with open(org_config_path, "r") as f:
                org_config = yaml.safe_load(f) or {}
            github_token = os.getenv("GITHUB_TOKEN") or org_config.get("GITHUB_TOKEN") or org_config.get("github", {}).get("token")
            org_name = os.getenv("ORG_NAME") or org_config.get("org_name") or org_config.get("github", {}).get("org_name")
        if not github_token or not org_name:
            raise ValueError("GITHUB_TOKEN and org_name (or config/org_config.yaml) required when skip_reachability is false")

    LOG.info("Phase 1: Resolved dependencies")
    deps = run_phase1_resolved_dependencies()
    if not deps:
        LOG.warning("No dependencies; nothing to check.")
        from dementor_sca import REPO_ROOT
        report_path_default = REPO_ROOT / "vulnerability_report_confirmed.json"
        with open(report_path_default, "w") as f:
            json.dump([], f, indent=2)
        return

    LOG.info("Phase 2: OSV check")
    potential = run_phase2_osv_check(deps)
    skip_reach = zfp.get("skip_reachability", False)
    if skip_reach:
        LOG.info("Phase 3 & 4: Skipped (skip_reachability: true). Report OSV-only findings; run reachability per-item (e.g. from dashboard).")
        with_reach = potential
        for entry in with_reach:
            entry["reachability_evidence"] = []
            entry["llm_confirms_vuln"] = False
            entry["reachability_analysis"] = {"notes": "Reachability skipped; check manually (e.g. Run Reachability Scan in dashboard)."}
        confirmed = with_reach
    else:
        LOG.info("Phase 3: Reachability (drop if not used)")
        with_reach = run_phase3_reachability(potential, github_token, org_name)
        LOG.info("Phase 4: LLM gate (keep only LLM-confirmed exploitable)")
        confirmed = run_phase4_llm_gate(with_reach, zfp.get("llm_confirm_gate", zfp.get("ollama_confirm_gate", True)))

    # Enrich with priority for prioritization: vulnerable code path vs support-only (see docs/VULNERABLE_CODE_PATH_PRIORITIZATION.md)
    for entry in confirmed:
        ra = entry.get("reachability_analysis") or {}
        if ra.get("notes", "").startswith("Reachability skipped"):
            entry["priority"] = "medium"
            entry["usage_confidence"] = "reachability_skipped_check_manually"
        else:
            entry["priority"] = "high"
            entry["usage_confidence"] = "vulnerable_code_path_confirmed"
        has_symbols = any(
            vuln.get("vulnerability_usage_analysis")
            for vuln in entry.get("vulnerabilities", [])
        )
        entry["had_vulnerable_symbols_in_osv"] = bool(has_symbols)

    report_path = zfp.get("report_path", "vulnerability_report_confirmed.json")
    from dementor_sca import REPO_ROOT
    report_path_resolved = REPO_ROOT / report_path if not os.path.isabs(report_path) else Path(report_path)
    with open(report_path_resolved, "w") as f:
        json.dump(confirmed, f, indent=2)
    LOG.info("Wrote %d confirmed findings to %s", len(confirmed), report_path_resolved)


if __name__ == "__main__":
    main()
