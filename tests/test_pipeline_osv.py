"""Regression tests for run_phase2_osv_check (dementor_sca.pipeline_zero_fp).

Guards a real bug found via the end-to-end self-test: PyPI package names must be normalized
(lowercased) before querying OSV, otherwise e.g. "PyYAML" returns ZERO vulns and the finding is
silently dropped — which had been hiding every uppercase-named PyPI vuln (PyYAML, Django, Pillow…)
from the zero-FP / dashboard scan path.

Offline: the OSV network calls are stubbed; no findings are produced so threat-intel enrichment
short-circuits without network.

Run standalone:  python tests/test_pipeline_osv.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dementor_sca import sca_osv, pipeline_zero_fp


def _with_stubbed_osv(deps):
    """Run run_phase2_osv_check with OSV stubbed; return the queries it sent."""
    captured = {"queries": []}
    orig_chunk = sca_osv.fetch_vulns_for_chunk

    def fake_chunk(chunk):
        captured["queries"].extend(chunk)
        return {"results": [{} for _ in chunk]}  # no "vulns" key -> no findings

    sca_osv.fetch_vulns_for_chunk = fake_chunk
    try:
        pipeline_zero_fp.run_phase2_osv_check(deps)
    finally:
        sca_osv.fetch_vulns_for_chunk = orig_chunk
    return captured["queries"]


def test_pypi_name_is_lowercased_for_osv():
    deps = [{"ecosystem": "pypi", "file": "/tmp/none/requirements.txt",
             "library": "PyYAML", "version": "5.1"}]
    queries = _with_stubbed_osv(deps)
    names = [q["package"]["name"] for q in queries]
    assert "pyyaml" in names, f"expected normalized 'pyyaml', got {names}"
    assert "PyYAML" not in names, "raw mixed-case name must NOT be sent to OSV (PyPI is normalized)"


def test_pypi_ecosystem_label_normalized():
    deps = [{"ecosystem": "pypi", "file": "/tmp/none/requirements.txt",
             "library": "Django", "version": "3.0"}]
    queries = _with_stubbed_osv(deps)
    ecos = {q["package"]["ecosystem"] for q in queries}
    assert ecos == {"PyPI"}, f"expected OSV ecosystem 'PyPI', got {ecos}"


def test_npm_name_case_preserved():
    # npm names are case-sensitive in OSV — must NOT be lowercased.
    deps = [{"ecosystem": "npm", "file": "/tmp/none/package.json",
             "library": "JSONStream", "version": "1.0.0"}]
    queries = _with_stubbed_osv(deps)
    names = [q["package"]["name"] for q in queries]
    assert "JSONStream" in names, f"npm name must be preserved as-is, got {names}"


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
