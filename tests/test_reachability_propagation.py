"""Regression tests for reachability verdict propagation (pipeline_zero_fp._reachability_for_entry).

Guards a real bug: the per-entry reachability merge dropped `is_used` and `reachability_analysis`,
copying only `evidence` + `llm_confirms_vuln`. The dashboard then rendered an EMPTY analysis as
all-"No" (Declared/Imported/Vulnerable-API) while `llm_confirms_vuln` separately drove
"Active exploit: Yes" — a self-contradicting panel (e.g. requests showing Active exploit=Yes but
Imported=No). The full reconciled analysis must propagate through.

Run standalone:  python tests/test_reachability_propagation.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dementor_sca import reachability_scan as rs
from dementor_sca.pipeline_zero_fp import _reachability_for_entry


def _run_with_fake_scan(fake_result, entry):
    orig = rs.scan_for_reachability
    rs.scan_for_reachability = lambda **kw: fake_result
    try:
        return _reachability_for_entry(entry, "tok", "org")
    finally:
        rs.scan_for_reachability = orig


def _entry():
    return {"library": "requests", "version_in_use": "2.32.3",
            "file_location": "/x/REPOSITORIES/example-repo/requirements.txt",
            "vulnerabilities": []}


def test_full_analysis_propagates():
    result = {
        "is_used": True,
        "llm_confirms_vuln": True,
        "vulnerable_function_reached": True,
        "evidence": [{"file": "auth.py", "line": 20}],
        "reachability_analysis": {
            "declared": True, "imported": True, "vulnerable_api_used": True,
            "active_exploit": True, "notes": "confirmed",
        },
    }
    out = _run_with_fake_scan(result, _entry())
    assert out is not None
    # The whole analysis must come through — not an empty dict.
    ra = out["reachability_analysis"]
    assert ra and ra.get("imported") is True and ra.get("active_exploit") is True
    assert out["is_used"] is True
    assert out["vulnerable_function_reached"] is True
    assert out["reachability_evidence"] == [{"file": "auth.py", "line": 20}]


def test_panel_is_internally_consistent():
    # Import-only finding: imported True, but vuln API not used -> active exploit must be False.
    # This mirrors the requests case; the panel must NOT show active=Yes with imported/api=No.
    result = {
        "is_used": True,
        "llm_confirms_vuln": False,
        "vulnerable_function_reached": False,
        "evidence": [{"file": "auth.py", "line": 20, "usage_summary": "import only"}],
        "reachability_analysis": {
            "declared": True, "imported": True, "vulnerable_api_used": False,
            "active_exploit": False, "notes": "import only",
        },
    }
    out = _run_with_fake_scan(result, _entry())
    ra = out["reachability_analysis"]
    # active_exploit and llm_confirms_vuln agree (both False); imported is True (not contradicting)
    assert ra["active_exploit"] is False
    assert out["llm_confirms_vuln"] is False
    assert ra["imported"] is True
    # invariant: active_exploit implies vulnerable_api_used
    assert not (ra["active_exploit"] and not ra["vulnerable_api_used"])


def test_drops_when_not_used():
    out = _run_with_fake_scan({"is_used": False}, _entry())
    assert out is None


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  ok  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"FAIL  {fn.__name__}: {e}")
        except Exception as e:
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
