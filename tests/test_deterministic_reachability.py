"""Tests for deterministic (no-AI) reachability — the 'Normal scan' engine.

Normal mode must produce a real reachability verdict WITHOUT any LLM call: a known
vulnerable symbol that is actually CALLED → vulnerable_api_used/vulnerable_function_reached,
but exploitability (active_exploit) is never asserted (that needs the AI scan).

Run standalone:  python tests/test_deterministic_reachability.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dementor_sca.reachability_scan import _symbols_called_in_snippet, _deterministic_usage


class _FakeSlice:
    def __init__(self, sink_function, caller_count=0, files_involved=("a.py",)):
        self.sink_function = sink_function
        self.caller_count = caller_count
        self.files_involved = list(files_involved)


def test_regex_detects_called_symbol():
    snip = "import yaml\n\ndef parse(s):\n    return yaml.load(s)\n"
    assert _symbols_called_in_snippet(snip, ["yaml.load"]) == ["yaml.load"]


def test_regex_ignores_symbol_only_imported_not_called():
    snip = "import yaml  # yaml.load is dangerous but not used here\n"
    assert _symbols_called_in_snippet(snip, ["yaml.load"]) == []


def test_regex_matches_last_dotted_component():
    snip = "ObjectInputStream in = ...; in.readObject();"
    assert _symbols_called_in_snippet(snip, ["ObjectInputStream.readObject"]) == ["ObjectInputStream.readObject"]


def test_generic_names_never_match():
    # `require`, `import`, `length`, `get`… appear in nearly every file — matching them as a
    # library's vulnerable API is a false positive (e.g. handlebars flagged via `require(`).
    snip = "const hb = require('handlebars'); const n = arr.length; obj.get(k);"
    assert _symbols_called_in_snippet(snip, ["require", "length", "get", "import"]) == []


def test_generic_matches_only_when_library_qualified():
    # A real vuln CAN be a generic-named method — we still catch it, but only qualified by the
    # library's own alias (no false-negative), never as a bare call (no false-positive).
    snip = "cache.get(key); other.get(x);"
    assert _symbols_called_in_snippet(snip, ["get"], aliases=["cache"]) == ["get"]   # cache.get( ✓
    assert _symbols_called_in_snippet(snip, ["get"], aliases=[]) == []               # bare → skipped


def test_lang_builtin_never_matches_even_qualified():
    # 'require' is a language builtin — never a library's vulnerable API, in any form.
    assert _symbols_called_in_snippet("x = require('lib')", ["require"], aliases=["lib"]) == []


def test_deterministic_verdict_from_callgraph_slice():
    d = _deterministic_usage("code", "pyyaml", ["yaml.load"], "code",
                             _FakeSlice("parse", caller_count=2))
    assert d["vulnerable_api_used"] is True
    assert d["vulnerable_function_reached"] is True
    assert d["confidence"] == "high"          # callers found → high
    assert d["active_exploit"] is False        # NEVER asserted deterministically
    assert d["analysis_mode"] == "deterministic"


def test_deterministic_verdict_from_regex_fallback():
    snip = "import yaml\nyaml.load(open('x'))\n"
    d = _deterministic_usage(snip, "pyyaml", ["yaml.load"], "code", None)
    assert d["vulnerable_api_used"] is True
    assert d["confidence"] == "medium"         # regex only → medium
    assert d["active_exploit"] is False
    assert "yaml.load" in d["apis_called"]


def test_deterministic_imported_but_not_called():
    snip = "import yaml  # not called\n"
    d = _deterministic_usage(snip, "pyyaml", ["yaml.load"], "code", None)
    assert d["vulnerable_api_used"] is False
    assert d["vulnerable_function_reached"] is False
    assert d["active_exploit"] is False


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
