"""Tests for threat-intel enrichment (dementor_sca.threat_intel).

EPSS (exploit probability) + CISA KEV (actively-exploited) rank the urgency of REAL findings.
These tests stub the two network sources so they run offline and deterministically, and verify:
field attachment, max-EPSS/KEV-any rollup across multiple CVEs, the threat_level bands, and
graceful behaviour when the sources return nothing.

Run standalone:  python tests/test_threat_intel.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dementor_sca import threat_intel
from dementor_sca.threat_intel import threat_level, enrich_findings


def _stub_sources(monkey_epss: dict, monkey_kev: set):
    threat_intel.fetch_epss = lambda cve_ids: {k: v for k, v in monkey_epss.items()}
    threat_intel.load_kev_catalog = lambda force=False: set(monkey_kev)


def _finding(*vulns):
    return {"library": "x", "version_in_use": "1.0", "vulnerabilities": list(vulns)}


def test_attaches_epss_and_kev_fields():
    _stub_sources({"CVE-2021-44228": {"score": 0.944, "percentile": 0.9998}},
                  {"CVE-2021-44228"})
    findings = [_finding({"osv_id": "GHSA-x", "cve_ids": ["CVE-2021-44228"], "severity": "CRITICAL"})]
    enrich_findings(findings)
    v = findings[0]["vulnerabilities"][0]
    assert v["epss_score"] == 0.944
    assert v["epss_percentile"] == 0.9998
    assert v["cisa_kev"] is True
    assert findings[0]["actively_exploited"] is True
    assert findings[0]["threat_level"] == "actively_exploited"
    assert findings[0]["max_epss"] == 0.944


def test_max_epss_and_kev_any_across_multiple_cves():
    _stub_sources({"CVE-A": {"score": 0.10, "percentile": 0.4},
                   "CVE-B": {"score": 0.80, "percentile": 0.95}},
                  {"CVE-B"})
    findings = [_finding({"osv_id": "OSV-1", "cve_ids": ["CVE-A", "CVE-B"]})]
    enrich_findings(findings)
    v = findings[0]["vulnerabilities"][0]
    assert v["epss_score"] == 0.80          # takes the max of the two
    assert v["cisa_kev"] is True            # KEV-if-any
    assert findings[0]["threat_level"] == "actively_exploited"


def test_threat_level_bands():
    assert threat_level(0.0, True) == "actively_exploited"   # KEV always wins
    assert threat_level(0.99, True) == "actively_exploited"
    assert threat_level(0.60, False) == "high_epss"
    assert threat_level(0.20, False) == "elevated"
    assert threat_level(0.01, False) == "low"


def test_no_cve_ids_gets_safe_defaults():
    _stub_sources({"CVE-Z": {"score": 0.9, "percentile": 0.99}}, {"CVE-Z"})
    findings = [_finding({"osv_id": "GHSA-only", "cve_ids": []})]  # GHSA with no CVE alias
    enrich_findings(findings)
    v = findings[0]["vulnerabilities"][0]
    assert v["epss_score"] == 0.0
    assert v["cisa_kev"] is False
    assert findings[0]["threat_level"] == "low"


def test_graceful_when_sources_empty():
    _stub_sources({}, set())                # both sources return nothing (e.g. offline)
    findings = [_finding({"osv_id": "OSV-1", "cve_ids": ["CVE-2099-0001"], "severity": "HIGH"})]
    enrich_findings(findings)               # must not raise
    v = findings[0]["vulnerabilities"][0]
    assert v["epss_score"] == 0.0
    assert v["cisa_kev"] is False
    assert findings[0]["threat_level"] == "low"


def test_empty_findings():
    assert enrich_findings([]) == []


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ok  {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL  {fn.__name__}: {e}")
        except Exception as e:
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
