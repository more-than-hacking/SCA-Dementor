"""Regression tests for distribution-name vs import-name reachability detection.

Bug (P0): the reachability grep searched for the *distribution* name (e.g. "pyyaml")
while source code imports the *module* name (e.g. "yaml"). When they differ the
library-presence check failed and the CVE was silently dropped as "not used".

Run standalone (no pytest needed):  python tests/test_reachability_naming.py
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dementor_sca.reachability_scan import (
    build_patterns_reachability,
    grep_library_usage_reachability,
    _import_aliases,
    _module_prefixes_from_symbols,
)


def _detect(lib, code, symbols):
    d = Path(tempfile.mkdtemp())
    f = d / "sample.py"
    f.write_text(code)
    patterns = build_patterns_reachability(symbols, lib)
    return bool(grep_library_usage_reachability(f, lib, patterns, symbols=symbols))


def test_distribution_name_mismatch_detected_via_symbols():
    # OSV reports lib "pyyaml"; symbols carry the real module ("yaml.load").
    assert _detect("pyyaml", "import yaml\nyaml.load(open('f'))\n", ["yaml.load", "load"])
    assert _detect("pyyaml", "from yaml import load\nload(data)\n", ["yaml.load"])


def test_distribution_name_mismatch_detected_via_alias_map():
    # No symbols — must fall back to the curated alias map.
    assert _detect("Pillow", "from PIL import Image\nImage.open('x')\n", [])
    assert _detect("scikit-learn", "import sklearn\nsklearn.cluster.KMeans()\n", [])
    assert _detect("opencv-python", "import cv2\ncv2.imread('x')\n", [])


def test_matching_name_still_works():
    assert _detect("yaml", "import yaml\nyaml.load(d)\n", ["yaml.load"])


def test_unrelated_file_not_flagged():
    assert not _detect("pyyaml", "import os\nos.getcwd()\n", ["yaml.load"])


def test_large_file_windows_on_the_call():
    # The vulnerable call sits ~10KB down — past the old 6000-char head cutoff.
    from dementor_sca.reachability_scan import build_patterns_reachability, grep_library_usage_reachability
    import tempfile
    big = "import yaml\n" + ("# filler padding padding padding\n" * 280) + "x = yaml.load(user_data)\n"
    assert len(big) > 8000
    d = Path(tempfile.mkdtemp()); f = d / "big.py"; f.write_text(big)
    pats = build_patterns_reachability(["yaml.load", "load"], "pyyaml")
    hits = grep_library_usage_reachability(f, "pyyaml", pats, symbols=["yaml.load", "load"])
    assert hits, "large file with a real call must still be detected"
    # The window must include the actual call, not just the head/import.
    assert "yaml.load(user_data)" in hits[0]["context_snippet"]


def test_relevance_prioritises_symbol_bearing_files():
    from dementor_sca.reachability_scan import _file_relevance
    syms = ["sslmode", "scramMaxIterations"]
    hot = _file_relevance(Path("application-prod.properties"),
                          [{"context_snippet": "jdbc:postgresql://h?sslmode=verify-full"}], syms)
    cold = _file_relevance(Path("Foo.java"),
                           [{"context_snippet": "import org.postgresql.Driver;"}], syms)
    assert hot > cold and hot >= 100   # symbol-bearing config ranked far above import-only


def test_alias_helpers():
    assert "yaml" in _import_aliases("PyYAML")
    assert "bs4" in _import_aliases("beautifulsoup4")
    assert "dateutil" in _import_aliases("python-dateutil")
    assert _import_aliases("org.apache.commons:commons-lang3") == set()  # Maven skipped
    assert _module_prefixes_from_symbols(["yaml.load", "os.system"]) == {"yaml", "os"}
    assert _module_prefixes_from_symbols(["load"]) == set()  # no module prefix


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
