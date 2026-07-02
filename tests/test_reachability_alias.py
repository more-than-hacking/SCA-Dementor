"""Regression tests for alias-aware window centering + manifest-not-usage (reachability_scan).

Found by deep-auditing a real scan:
  - PyJWT false-negative: `import jwt as _jwt; _jwt.decode(...)` was missed because the window
    centered on an earlier generic `.get(`. The window must center on a QUALIFIED call to the
    library's own module/alias — and this must work in EVERY language, not just Python.
  - Manifest != usage: a library in its own requirements.txt/pom.xml is declared, not used.

These tests exercise the alias forms across Python, JavaScript/TS, and Go.

Run standalone:  python tests/test_reachability_alias.py
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dementor_sca import reachability_scan as R


def _grep(filename: str, code: str, library: str, symbols: list):
    prefixes = list(R._generate_package_prefixes(
        library.split(":")[0], library.split(":")[-1], library, symbols=symbols))
    pats = R.build_patterns_reachability(prefixes, library)
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / filename
        f.write_text(code, "utf-8")
        return R.grep_library_usage_reachability(f, library, pats, symbols=symbols)


def _centers_on(usages, needle):
    return bool(usages) and needle in usages[0]["context_snippet"]


# ---------------- Python ----------------
def test_py_module_alias():
    code = ("import jwt as _jwt\n" + "x = {}.get('a')\n" + "# pad\n" * 40 +
            "def v(t):\n    return _jwt.decode(t, 's', algorithms=['HS256'])\n")
    assert _centers_on(_grep("auth.py", code, "PyJWT", ["jwt.decode", "decode"]), "_jwt.decode")


def test_py_symbol_alias_bare_call():
    code = ("from jwt import decode as d\n" + "y = {}.get('a')\n" + "# pad\n" * 40 +
            "def v(t):\n    return d(t, 's', algorithms=['HS256'])\n")
    u = _grep("auth.py", code, "PyJWT", ["jwt.decode", "decode"])
    assert _centers_on(u, "d(t")  # the bare symbol-alias call


def test_py_plain_qualified_still_works():
    code = "import jwt\n\ndef v(t):\n    return jwt.decode(t, 'k', algorithms=['HS256'])\n"
    assert _centers_on(_grep("svc.py", code, "PyJWT", ["jwt.decode", "decode"]), "jwt.decode")


# ---------------- JavaScript / TypeScript ----------------
def test_js_require_alias():
    code = ("const _ = require('lodash');\n" + "const z = obj.get('k');\n" + "// pad\n" * 40 +
            "function build(i){ return _.defaultsDeep({}, i); }\n")
    assert _centers_on(_grep("index.js", code, "lodash", ["defaultsDeep"]), "_.defaultsDeep")


def test_js_namespace_import_alias():
    code = ("import * as jsonwebtoken from 'jsonwebtoken';\n" + "// pad\n" * 30 +
            "export function check(t){ return jsonwebtoken.verify(t, key); }\n")
    assert _centers_on(_grep("auth.ts", code, "jsonwebtoken", ["verify", "decode"]), "jsonwebtoken.verify")


def test_js_named_symbol_alias():
    code = ("import { defaultsDeep as dd } from 'lodash';\n" + "// pad\n" * 30 +
            "function build(i){ return dd({}, i); }\n")
    assert _centers_on(_grep("index.js", code, "lodash", ["defaultsDeep"]), "dd({}")


# ---------------- Go ----------------
def test_go_import_alias():
    code = ('package main\n\nimport y "gopkg.in/yaml.v2"\n\n'
            "func parse(b []byte) error {\n    var o map[string]interface{}\n"
            "    return y.Unmarshal(b, &o)\n}\n")
    assert _centers_on(_grep("main.go", code, "gopkg.in/yaml.v2", ["Unmarshal"]), "y.Unmarshal")


def test_go_block_import_alias():
    code = ('package main\n\nimport (\n    "fmt"\n    yaml "gopkg.in/yaml.v2"\n)\n\n'
            "func parse(b []byte) error {\n    _ = fmt.Sprint\n"
            "    var o map[string]interface{}\n    return yaml.Unmarshal(b, &o)\n}\n")
    assert _centers_on(_grep("main.go", code, "gopkg.in/yaml.v2", ["Unmarshal"]), "yaml.Unmarshal")


# ---------------- Manifest != usage ----------------
def test_manifest_not_usage():
    for name in ("requirements.txt", "requirements-heavy.txt", "package.json", "pom.xml", "go.mod"):
        u = _grep(name, "lodash\nPyJWT\nyaml\n", "lodash", ["defaultsDeep"])
        assert u == [], f"{name} must not count as usage"


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
