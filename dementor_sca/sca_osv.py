# OSV-based vulnerability check + latest-version verification (no LLM)

import json
import os
import requests
import argparse
import importlib
import yaml
from pathlib import Path
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from packaging.version import Version, InvalidVersion

from dementor_sca import REPO_ROOT

MAX_QUERIES_PER_BATCH = 1000
MAX_WORKERS = 15
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_SINGLE_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"


def normalize_ecosystem(name: str) -> str:
    mapping = {"maven": "Maven", "pypi": "PyPI", "npm": "npm", "golang": "Go", "go": "Go", "nuget": "NuGet", "rubygems": "RubyGems"}
    return mapping.get(name.lower(), name)


def normalize_package_name(name: str, ecosystem: str) -> str:
    """OSV/PyPI expects lowercase package names; use as-is for other ecosystems."""
    if not name:
        return name
    if ecosystem and ecosystem.lower() == "pypi":
        return name.lower()
    return name


def load_json_file(filepath: str) -> list:
    if not os.path.exists(filepath):
        print(f"Error: Input file not found at '{filepath}'")
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            seen = set()
            unique_libs = []
            for lib in json.load(f):
                identifier = f"{lib.get('library')}@{lib.get('version')}"
                if identifier not in seen:
                    seen.add(identifier)
                    unique_libs.append(lib)
            return unique_libs
    except Exception as e:
        print(f"Error reading '{filepath}': {e}")
        return []


def fetch_latest_version(library_name: str, ecosystem: str, parser_config: dict) -> str | None:
    parser_path = parser_config.get(ecosystem.strip())
    if not parser_path:
        return None
    try:
        module = importlib.import_module(parser_path)
        return module.fetch_latest_version(library_name)
    except Exception as e:
        print(f"[WARN] Failed to fetch latest version for {library_name}: {e}")
        return None


def check_version_vulnerabilities(name: str, version: str, ecosystem: str) -> list:
    if not all([name, version, ecosystem]):
        return []
    try:
        q = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
        with requests.Session() as s:
            r = s.post(OSV_SINGLE_URL, json=q, timeout=15)
            r.raise_for_status()
            return [v["id"] for v in r.json().get("vulns", [])]
    except Exception:
        return []


def fetch_vulns_for_chunk(chunk: list) -> dict:
    try:
        with requests.Session() as s:
            r = s.post(OSV_BATCH_URL, json={"queries": chunk}, timeout=60)
            r.raise_for_status()
            return r.json()
    except Exception:
        return {"results": []}


def fetch_vuln_details(osv_id: str) -> dict:
    try:
        with requests.Session() as s:
            r = s.get(f"{OSV_VULN_URL}{osv_id}", timeout=10)
            r.raise_for_status()
            return r.json()
    except Exception:
        return {"id": osv_id, "error": "Failed to fetch details"}


def extract_severity(vuln: dict) -> str:
    db = vuln.get("database_specific", {})
    if isinstance(db, dict):
        sev = db.get("severity", "N/A")
        if isinstance(sev, str):
            return sev.upper()
    return "N/A"


def find_best_safer_version(current: str, vulns: list, lib_name: str) -> str | None:
    try:
        current_v = Version(current)
    except InvalidVersion:
        return None
    upgrades = []
    for vuln in vulns:
        for aff in vuln.get("affected", []):
            if aff.get("package", {}).get("name") != lib_name:
                continue
            for r in aff.get("ranges", []):
                for e in r.get("events", []):
                    if "fixed" in e:
                        try:
                            fix_v = Version(e["fixed"])
                            if fix_v > current_v:
                                upgrades.append(fix_v)
                        except InvalidVersion:
                            continue
    return str(max(upgrades)) if upgrades else None


def _available_versions(name: str, ecosystem: str) -> list:
    """Return sorted real released versions from the package registry (npm / PyPI).
    Empty list if the ecosystem isn't verifiable here or the fetch fails."""
    eco = (ecosystem or "").lower()
    versions = []
    try:
        if eco in ("npm", "npmjs"):
            r = requests.get(f"https://registry.npmjs.org/{name}", timeout=10)
            r.raise_for_status()
            versions = list((r.json().get("versions") or {}).keys())
        elif eco in ("pypi", "python"):
            r = requests.get(f"https://pypi.org/pypi/{name}/json", timeout=10)
            r.raise_for_status()
            versions = list((r.json().get("releases") or {}).keys())
        else:
            return []   # Maven/Go/etc. — not verified here
    except Exception:
        return []
    out = []
    for v in versions:
        try:
            pv = Version(v)
            if pv.is_prerelease or pv.is_devrelease:
                continue          # never recommend an rc/alpha/beta/dev release
            out.append(pv)
        except InvalidVersion:
            continue
    return sorted(out)


def safest_available_upgrade(current: str, vulns: list, lib_name: str, ecosystem: str = "") -> dict | None:
    """Recommend a REAL, available upgrade that fixes all matched CVEs.

    Takes the OSV fix target (max 'fixed' across CVEs), then snaps it to an actually-released
    version: the smallest available version >= the target. If no released version reaches the
    target (even the latest is still affected), recommends the latest available and flags it.
    Returns None if there's no fix above the current version.
    """
    target = find_best_safer_version(current, vulns, lib_name)
    if not target:
        return None
    avail = _available_versions(lib_name, ecosystem)
    if not avail:
        # Can't verify availability (unsupported ecosystem / offline) — surface the OSV target.
        return {"minimal_safer_version": target, "latest_version": target,
                "latest_is_vulnerable": False, "verified": False}
    try:
        tv = Version(target)
    except InvalidVersion:
        return {"minimal_safer_version": target, "latest_version": str(avail[-1]),
                "latest_is_vulnerable": False, "verified": False}
    latest = str(avail[-1])
    at_or_above = [v for v in avail if v >= tv]
    if at_or_above:
        return {"minimal_safer_version": str(min(at_or_above)), "latest_version": latest,
                "latest_is_vulnerable": False, "verified": True}
    # No released version reaches the fix target → even the latest is still affected.
    return {"minimal_safer_version": latest, "latest_version": latest,
            "latest_is_vulnerable": True, "verified": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="dependency_results.json")
    parser.add_argument("--prefer", choices=["safer", "latest"], default="latest")
    parser.add_argument("--html", action="store_true")
    args = parser.parse_args()

    parser_config_path = Path(__file__).parent / "latest_version_parsers" / "parser_config.yaml"
    with open(parser_config_path) as f:
        parser_config = yaml.safe_load(f).get("latest-version_parsers", {})

    input_path = REPO_ROOT / args.input if not os.path.isabs(args.input) else args.input
    print("--- Hybrid Vulnerability Scan ---")
    libs = load_json_file(str(input_path))
    queries, query_map = [], {}
    for lib in libs:
        eco = normalize_ecosystem(lib.get("ecosystem", ""))
        name_raw, ver = lib.get("library"), lib.get("version")
        name = normalize_package_name(name_raw, eco) if name_raw else None
        if name and ver and eco:
            q = {"version": ver, "package": {"name": name, "ecosystem": eco}}
            queries.append(q)
            query_map[(name, ver, eco)] = lib

    vuln_map, all_ids = {}, set()
    chunks = [queries[i : i + MAX_QUERIES_PER_BATCH] for i in range(0, len(queries), MAX_QUERIES_PER_BATCH)]
    with ThreadPoolExecutor(MAX_WORKERS) as ex:
        fut_map = {ex.submit(fetch_vulns_for_chunk, c): c for c in chunks}
        for fut in tqdm(as_completed(fut_map), total=len(fut_map), desc="Discovering vulns"):
            for i, res in enumerate(fut.result().get("results", [])):
                if "vulns" in res:
                    q = fut_map[fut][i]
                    k = (q["package"]["name"], q["version"], q["package"]["ecosystem"])
                    vuln_map[k] = [v["id"] for v in res["vulns"]]
                    all_ids.update(v["id"] for v in res["vulns"])

    details_map = {}
    with ThreadPoolExecutor(MAX_WORKERS) as ex:
        futs = {ex.submit(fetch_vuln_details, oid): oid for oid in all_ids}
        for fut in tqdm(as_completed(futs), total=len(futs), desc="Fetching details"):
            res = fut.result()
            details_map[res.get("id")] = res

    latest_map = {}
    uniq = {(k[0], k[2]) for k in vuln_map}
    with ThreadPoolExecutor(MAX_WORKERS) as ex:
        futs = {ex.submit(fetch_latest_version, n, e, parser_config): n for n, e in uniq}
        for fut in tqdm(as_completed(futs), total=len(futs), desc="Fetching latest"):
            latest_map[futs[fut]] = fut.result()

    verify_map = {}
    to_check = [(n, latest_map[n], e) for (n, e) in uniq if latest_map.get(n)]
    with ThreadPoolExecutor(MAX_WORKERS) as ex:
        futs = {ex.submit(check_version_vulnerabilities, n, v, e): n for n, v, e in to_check}
        for fut in tqdm(as_completed(futs), total=len(futs), desc="Verifying latest"):
            verify_map[futs[fut]] = fut.result()

    report, fp_count = [], 0
    for k, ids in tqdm(vuln_map.items(), desc="Generating report"):
        lib = query_map[k]
        name = lib["library"]
        name_norm = k[0]
        relevant = [
            details_map[i]
            for i in ids
            if not details_map.get(i, {}).get("error")
            and any(a.get("package", {}).get("name", "").lower() == name_norm.lower() for a in details_map[i].get("affected", []))
        ]
        fp_count += len(ids) - len(relevant)
        if not relevant:
            continue

        safer_v = find_best_safer_version(lib["version"], relevant, name_norm)
        latest_v = latest_map.get(name_norm)
        latest_vuln = bool(verify_map.get(name_norm))

        recommendation = "Manual review required."
        if safer_v:
            recommendation = f"Upgrade to minimal safer version ({safer_v})."
            try:
                if latest_v and Version(latest_v) > Version(safer_v):
                    recommendation = f"Upgrade to latest version ({latest_v})."
                    if latest_vuln:
                        recommendation += " CAUTION: latest version has vulnerabilities."
            except InvalidVersion:
                recommendation += " NOTE: latest version not comparable."

        report.append({
            "library": name,
            "version_in_use": lib["version"],
            "file_location": lib["file"],
            "upgrade_recommendation": {
                "minimal_safer_version": safer_v,
                "latest_version": latest_v,
                "latest_is_vulnerable": latest_vuln,
                "latest_version_vulns": verify_map.get(name_norm, []),
                "recommendation": recommendation,
            },
            "vulnerabilities": [
                {
                    "osv_id": v.get("id"),
                    "cve_ids": [c for c in v.get("aliases", []) if "CVE" in c],
                    "severity": extract_severity(v),
                    "summary": v.get("summary"),
                    "details": v.get("details"),
                    "fixed_in_branch": next(
                        (e["fixed"] for a in v.get("affected", []) for r in a.get("ranges", []) for e in r.get("events", []) if "fixed" in e),
                        None,
                    ),
                    "published": v.get("published"),
                    "modified": v.get("modified"),
                }
                for v in relevant
            ],
        })

    out_path = REPO_ROOT / "vulnerability_report_live_verified.json"
    with open(out_path, "w") as f:
        json.dump(report, f, indent=4)
    print(f"\n✅ Report saved to '{out_path}'")
    if fp_count > 0:
        print(f"Filtered {fp_count} possible false positives.")


if __name__ == "__main__":
    main()
