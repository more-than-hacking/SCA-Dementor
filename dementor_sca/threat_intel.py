"""Threat-intelligence enrichment — EPSS exploit-probability + CISA KEV "exploited now" flag.

Severity alone cannot rank 50 "Critical" findings — they all look equally scary. Two free,
keyless, public sources fix that:

- **EPSS** (FIRST.org) — a daily-updated probability (0.0–1.0) that a CVE will be exploited in
  the next 30 days. `api.first.org/data/v1/epss?cve=CVE-…` (no key).
- **CISA KEV** — the U.S. government catalog of CVEs *confirmed exploited in the wild right now*.
  One JSON file, downloaded once and cached for the day (no key).

This is a pure **data-enrichment layer** and is deliberately decoupled from reachability:
reachability (Layer 1) decides whether a finding is REAL; EPSS/KEV (Layer 2) ranks the urgency
of the real ones. It attaches per-vulnerability `epss_score` / `epss_percentile` / `cisa_kev`
plus finding-level rollups (`max_epss`, `actively_exploited`, `threat_level`).

Resilient by design: any network/parse failure leaves findings untouched (defaults), never
raises, never blocks a scan — consistent with the keyless, "just-works" philosophy.
"""
from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

log = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_EPSS_CHUNK = 100          # CVEs per EPSS request (comma-joined query string)
_KEV_TTL_SECONDS = 86_400  # cache the KEV catalog for a day


# ---------------------------------------------------------------------------
# EPSS — exploit probability per CVE
# ---------------------------------------------------------------------------

def fetch_epss(cve_ids: list) -> dict:
    """Return {cve_id: {"score": float, "percentile": float}} for the CVEs that have EPSS data.

    EPSS only covers CVE IDs (not GHSA/GO-…). CVEs without a score simply won't appear in the
    result. Network failures yield an empty dict (callers treat missing as "no signal").
    """
    cves = sorted({c for c in cve_ids if c and c.upper().startswith("CVE-")})
    if not cves:
        return {}
    chunks = [cves[i:i + _EPSS_CHUNK] for i in range(0, len(cves), _EPSS_CHUNK)]
    out: dict = {}
    with ThreadPoolExecutor(min(8, len(chunks))) as ex:
        futs = {ex.submit(_fetch_epss_chunk, c): c for c in chunks}
        for fut in as_completed(futs):
            try:
                out.update(fut.result())
            except Exception as e:  # pragma: no cover - defensive
                log.debug("EPSS chunk failed: %s", e)
    return out


def _fetch_epss_chunk(cves: list) -> dict:
    try:
        with requests.Session() as s:
            r = s.get(EPSS_URL, params={"cve": ",".join(cves)}, timeout=20)
            r.raise_for_status()
            data = r.json().get("data", [])
    except Exception as e:
        log.debug("EPSS request failed: %s", e)
        return {}
    result: dict = {}
    for row in data:
        cve = row.get("cve")
        if not cve:
            continue
        try:
            result[cve] = {"score": float(row.get("epss", 0) or 0),
                           "percentile": float(row.get("percentile", 0) or 0)}
        except (TypeError, ValueError):
            continue
    return result


# ---------------------------------------------------------------------------
# CISA KEV — actively-exploited catalog (cached daily)
# ---------------------------------------------------------------------------

def _kev_cache_path() -> Path:
    from dementor_sca import REPO_ROOT
    return Path(REPO_ROOT) / ".cache" / "cisa_kev.json"


def load_kev_catalog(force: bool = False) -> set:
    """Return the set of CVE IDs in the CISA KEV catalog, cached on disk for a day.

    On network failure, falls back to a stale cache if present, else an empty set.
    """
    cache = _kev_cache_path()
    if not force and cache.is_file():
        try:
            age = time.time() - cache.stat().st_mtime
            if age < _KEV_TTL_SECONDS:
                return set(json.loads(cache.read_text("utf-8")))
        except Exception:
            pass  # fall through to refetch

    try:
        with requests.Session() as s:
            r = s.get(KEV_URL, timeout=30)
            r.raise_for_status()
            vulns = r.json().get("vulnerabilities", [])
        ids = sorted({v.get("cveID") for v in vulns if v.get("cveID")})
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(ids), "utf-8")
        except Exception as e:  # caching is best-effort
            log.debug("KEV cache write failed: %s", e)
        return set(ids)
    except Exception as e:
        log.debug("KEV fetch failed (%s); trying stale cache", e)
        if cache.is_file():
            try:
                return set(json.loads(cache.read_text("utf-8")))
            except Exception:
                pass
        return set()


# ---------------------------------------------------------------------------
# Enrichment + scoring
# ---------------------------------------------------------------------------

def threat_level(max_epss: float, actively_exploited: bool) -> str:
    """Coarse urgency band derived from EPSS + KEV (for sorting / badges)."""
    if actively_exploited:
        return "actively_exploited"   # on CISA KEV — exploited in the wild now
    if max_epss >= 0.5:
        return "high_epss"            # very likely to be exploited
    if max_epss >= 0.1:
        return "elevated"
    return "low"


def enrich_findings(findings: list) -> list:
    """Attach EPSS + CISA KEV signals to each finding's vulnerabilities, in place.

    Per vulnerability adds: `epss_score`, `epss_percentile`, `cisa_kev`.
    Per finding adds rollups: `max_epss`, `max_epss_percentile`, `actively_exploited`,
    `threat_level`. A finding/vuln with multiple CVE IDs takes the max EPSS and KEV-if-any.
    Network failures degrade gracefully (zeros / False), never raise.
    """
    if not findings:
        return findings

    all_cves = [c for f in findings for v in f.get("vulnerabilities", []) for c in v.get("cve_ids", [])]
    epss = fetch_epss(all_cves)
    kev = load_kev_catalog()

    for f in findings:
        f_max_epss, f_max_pct, f_kev = 0.0, 0.0, False
        for v in f.get("vulnerabilities", []):
            cves = v.get("cve_ids", []) or []
            v_score, v_pct = 0.0, 0.0
            for c in cves:
                d = epss.get(c)
                if d and d["score"] > v_score:
                    v_score, v_pct = d["score"], d["percentile"]
            v_kev = any(c in kev for c in cves)
            v["epss_score"] = round(v_score, 5)
            v["epss_percentile"] = round(v_pct, 5)
            v["cisa_kev"] = v_kev
            f_max_epss = max(f_max_epss, v_score)
            f_max_pct = max(f_max_pct, v_pct)
            f_kev = f_kev or v_kev
        f["max_epss"] = round(f_max_epss, 5)
        f["max_epss_percentile"] = round(f_max_pct, 5)
        f["actively_exploited"] = f_kev
        f["threat_level"] = threat_level(f_max_epss, f_kev)
    return findings
