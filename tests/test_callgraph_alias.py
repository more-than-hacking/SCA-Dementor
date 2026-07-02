"""Tests for symbol-alias resolution in the deterministic call graph (callgraph.py).

Brings the call-graph engine (used by the benchmark + flow-viz) to parity with the production
grep path: `from yaml import load as L; L(s)` and `import {decode as d} from 'jwt'; d(...)` are
now matched. Module aliases (`import jwt as _jwt; _jwt.decode`) already matched via trailing name.
Variable indirection (`fn = yaml.load; fn(s)`) remains a documented gap (needs data-flow).

Run standalone:  python tests/test_callgraph_alias.py
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dementor_sca.callgraph import build_reachability_paths, TREE_SITTER_AVAILABLE


def _reachable(filename, code, symbols):
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / filename).write_text(code, "utf-8")
        r = build_reachability_paths(d, d / filename, symbols)
        return bool(r and r.get("paths"))


def test_py_symbol_alias_resolved():
    assert _reachable("app.py",
                      "from yaml import load as L\n\ndef parse(s):\n    return L(s)\n",
                      ["yaml.load", "load"])


def test_py_module_alias_resolved():
    assert _reachable("app.py",
                      "import yaml as y\n\ndef parse(s):\n    return y.load(s)\n",
                      ["yaml.load", "load"])


def test_js_named_symbol_alias_resolved():
    assert _reachable("index.js",
                      "import { defaultsDeep as dd } from 'lodash'\nfunction b(x){ return dd({}, x); }\n",
                      ["defaultsDeep"])


def test_safe_alias_not_flagged():
    # Aliasing a NON-vulnerable symbol must NOT match the sink.
    assert not _reachable("app.py",
                          "from yaml import safe_load as sl\n\ndef parse(s):\n    return sl(s)\n",
                          ["yaml.load", "load"])


def test_variable_indirection_is_known_gap():
    # Documented limitation: call through a variable is NOT resolved (needs data-flow).
    assert not _reachable("app.py",
                          "import yaml\n\ndef parse(s):\n    fn = yaml.load\n    return fn(s)\n",
                          ["yaml.load", "load"])


if __name__ == "__main__":
    if not TREE_SITTER_AVAILABLE:
        print("tree-sitter unavailable — skipping"); sys.exit(0)
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
