"""Dementor reachability benchmark — the scoreboard.

Measures the CORE claim deterministically and offline (no LLM, no network): of the vulnerable
libraries that are *present* in a project (everything a naive version-match scanner flags), how
many does Dementor correctly confirm **reachable** vs. correctly suppress as **latent**?

Why this is honest:
- Uses only the *deterministic* engine — the tree-sitter call graph (`build_reachability_paths`)
  and the lockfile transitive resolver — NOT the LLM layer. Reproducible by anyone.
  (The LLM layer refines further; benchmark it separately once a provider is configured.)
- Ground truth is known *by construction*: each fixture is a tiny project where we know whether
  the vulnerable function is genuinely on a reachable call path.
- The "naive" baseline = flag every present vulnerable version (recall 100%, precision poor) —
  what ordinary SCA does. Dementor's value is the precision gain at no recall loss.
- Cases are modeled on REAL CVEs (PyYAML/yaml.load, lodash/defaultsDeep, SnakeYAML/load,
  gopkg.in/yaml.v2/Unmarshal). `KNOWN_GAP_CASES` documents patterns the *static core* misses
  today (honesty over cherry-picking).

Fixtures are inline (materialized to a temp dir per run): the whole benchmark is one transparent,
extensible file. Add a case = append to CASES.

Run:  python benchmark/run_benchmark.py
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dementor_sca.callgraph import build_reachability_paths
from dementor_sca.transitive_resolver import resolve_transitive_deps

SRC_EXTS = {".py", ".js", ".ts", ".java", ".go"}

_LOCK_NPM = (
    '{{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{{'
    '"":{{"name":"app","version":"1.0.0"}},'
    '"node_modules/express":{{"version":"4.18.2"}},'
    '"node_modules/lodash":{{"version":"4.17.4"}}}}}}\n'
).format()


# ---------------------------------------------------------------------------
# Supported cases — known ground truth, exercise patterns the engine handles.
#   expected_reachable=True  → vulnerable function genuinely on a reachable path
#   expected_reachable=False → vulnerable version present but NOT reachable (naive's false alarm)
# ---------------------------------------------------------------------------
CASES = [
    # ---- Python (PyYAML / yaml.load — CVE-2020-14343 family) ----
    {
        "name": "py_reachable_direct", "lang": "python",
        "desc": "PyYAML present; vulnerable yaml.load() called directly",
        "ecosystem": "pypi", "library": "PyYAML", "version": "5.1",
        "sink_symbols": ["yaml.load"], "expected_reachable": True, "dep_type": "direct",
        "files": {
            "requirements.txt": "PyYAML==5.1\n",
            "app.py": "import yaml\n\ndef parse(s):\n    return yaml.load(s)  # vulnerable: no Loader\n",
        },
    },
    {
        "name": "py_reachable_multihop", "lang": "python",
        "desc": "yaml.load() reached 3 hops down (main -> load_config -> _read -> yaml.load)",
        "ecosystem": "pypi", "library": "PyYAML", "version": "5.1",
        "sink_symbols": ["yaml.load"], "expected_reachable": True, "dep_type": "direct",
        "files": {
            "requirements.txt": "PyYAML==5.1\n",
            "app.py": (
                "import yaml\n\n"
                "def _read(s):\n    return yaml.load(s)  # sink\n\n"
                "def load_config(s):\n    return _read(s)\n\n"
                "def main():\n    return load_config('x')\n"
            ),
        },
    },
    {
        "name": "py_latent_safe_fn", "lang": "python",
        "desc": "PyYAML imported, but only the SAFE yaml.safe_load() is used",
        "ecosystem": "pypi", "library": "PyYAML", "version": "5.1",
        "sink_symbols": ["yaml.load"], "expected_reachable": False, "dep_type": "direct",
        "files": {
            "requirements.txt": "PyYAML==5.1\n",
            "app.py": "import yaml\n\ndef parse(s):\n    return yaml.safe_load(s)  # safe\n",
        },
    },
    {
        "name": "py_latent_unused", "lang": "python",
        "desc": "PyYAML declared in requirements but never imported or used",
        "ecosystem": "pypi", "library": "PyYAML", "version": "5.1",
        "sink_symbols": ["yaml.load"], "expected_reachable": False, "dep_type": "direct",
        "files": {
            "requirements.txt": "PyYAML==5.1\n",
            "app.py": "def add(a, b):\n    return a + b\n",
        },
    },

    # ---- JavaScript (lodash / defaultsDeep — CVE-2019-10744) ----
    {
        "name": "js_direct_reachable", "lang": "javascript",
        "desc": "lodash direct dep; vulnerable defaultsDeep() called",
        "ecosystem": "npm", "library": "lodash", "version": "4.17.4",
        "sink_symbols": ["defaultsDeep"], "expected_reachable": True, "dep_type": "direct",
        "files": {
            "package.json": '{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.4"}}\n',
            "index.js": (
                "const _ = require('lodash');\n"
                "function build(input) {\n  return _.defaultsDeep({}, input);  // vulnerable\n}\n"
                "module.exports = build;\n"
            ),
        },
    },
    {
        "name": "js_direct_latent", "lang": "javascript",
        "desc": "lodash direct dep, but only the safe _.get() is used",
        "ecosystem": "npm", "library": "lodash", "version": "4.17.4",
        "sink_symbols": ["defaultsDeep"], "expected_reachable": False, "dep_type": "direct",
        "files": {
            "package.json": '{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.4"}}\n',
            "index.js": (
                "const _ = require('lodash');\n"
                "function read(o) {\n  return _.get(o, 'a.b');  // safe\n}\n"
                "module.exports = read;\n"
            ),
        },
    },
    {
        "name": "js_transitive_reachable", "lang": "javascript",
        "desc": "lodash is TRANSITIVE (only in lockfile); vulnerable defaultsDeep() is called",
        "ecosystem": "npm", "library": "lodash", "version": "4.17.4",
        "sink_symbols": ["defaultsDeep"], "expected_reachable": True, "dep_type": "transitive",
        "direct": {"library": "express", "version": "4.18.2"},
        "files": {
            "package.json": '{"name":"app","version":"1.0.0","dependencies":{"express":"^4.18.0"}}\n',
            "package-lock.json": _LOCK_NPM,
            "index.js": (
                "const _ = require('lodash');\n"
                "function build(input) {\n  return _.defaultsDeep({}, input);  // vulnerable\n}\n"
                "module.exports = build;\n"
            ),
        },
    },
    {
        "name": "js_transitive_unused", "lang": "javascript",
        "desc": "lodash present transitively but its vulnerable fn is never called",
        "ecosystem": "npm", "library": "lodash", "version": "4.17.4",
        "sink_symbols": ["defaultsDeep"], "expected_reachable": False, "dep_type": "transitive",
        "direct": {"library": "express", "version": "4.18.2"},
        "files": {
            "package.json": '{"name":"app","version":"1.0.0","dependencies":{"express":"^4.18.0"}}\n',
            "package-lock.json": _LOCK_NPM,
            "index.js": (
                "const express = require('express');\n"
                "const app = express();\n"
                "app.get('/', (req, res) => res.send('hi'));\n"
            ),
        },
    },

    # ---- Java (SnakeYAML / load — CVE-2022-1471) ----
    {
        "name": "java_reachable", "lang": "java",
        "desc": "SnakeYAML present; vulnerable yaml.load() called",
        "ecosystem": "maven", "library": "org.yaml:snakeyaml", "version": "1.30",
        "sink_symbols": ["load"], "expected_reachable": True, "dep_type": "direct",
        "files": {
            "pom.xml": (
                "<project><dependencies><dependency>"
                "<groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>1.30</version>"
                "</dependency></dependencies></project>\n"
            ),
            "App.java": (
                "import org.yaml.snakeyaml.Yaml;\n"
                "public class App {\n"
                "  public Object parse(String s) {\n"
                "    Yaml yaml = new Yaml();\n"
                "    return yaml.load(s);  // vulnerable\n"
                "  }\n"
                "}\n"
            ),
        },
    },
    {
        "name": "java_latent", "lang": "java",
        "desc": "SnakeYAML present, but only the safe dump() is used",
        "ecosystem": "maven", "library": "org.yaml:snakeyaml", "version": "1.30",
        "sink_symbols": ["load"], "expected_reachable": False, "dep_type": "direct",
        "files": {
            "pom.xml": (
                "<project><dependencies><dependency>"
                "<groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>1.30</version>"
                "</dependency></dependencies></project>\n"
            ),
            "App.java": (
                "import org.yaml.snakeyaml.Yaml;\n"
                "public class App {\n"
                "  public String write(Object o) {\n"
                "    Yaml yaml = new Yaml();\n"
                "    return yaml.dump(o);  // safe\n"
                "  }\n"
                "}\n"
            ),
        },
    },

    # ---- Go (gopkg.in/yaml.v2 / Unmarshal — CVE-2019-11254) ----
    {
        "name": "go_reachable", "lang": "go",
        "desc": "yaml.v2 present; vulnerable yaml.Unmarshal() called",
        "ecosystem": "go", "library": "gopkg.in/yaml.v2", "version": "v2.2.2",
        "sink_symbols": ["Unmarshal"], "expected_reachable": True, "dep_type": "direct",
        "files": {
            "go.mod": "module example.com/app\n\ngo 1.20\n\nrequire gopkg.in/yaml.v2 v2.2.2\n",
            "main.go": (
                "package main\n\n"
                "import yaml \"gopkg.in/yaml.v2\"\n\n"
                "func parse(b []byte) error {\n"
                "    var out map[string]interface{}\n"
                "    return yaml.Unmarshal(b, &out)  // vulnerable\n"
                "}\n\n"
                "func main() { _ = parse(nil) }\n"
            ),
        },
    },
    {
        "name": "go_latent", "lang": "go",
        "desc": "yaml.v2 present, but only the safe Marshal() is used",
        "ecosystem": "go", "library": "gopkg.in/yaml.v2", "version": "v2.2.2",
        "sink_symbols": ["Unmarshal"], "expected_reachable": False, "dep_type": "direct",
        "files": {
            "go.mod": "module example.com/app\n\ngo 1.20\n\nrequire gopkg.in/yaml.v2 v2.2.2\n",
            "main.go": (
                "package main\n\n"
                "import yaml \"gopkg.in/yaml.v2\"\n\n"
                "func dump(v interface{}) ([]byte, error) {\n"
                "    return yaml.Marshal(v)  // safe\n"
                "}\n\n"
                "func main() { _, _ = dump(nil) }\n"
            ),
        },
    },
    {
        # Was a KNOWN GAP (alias tracking); now SUPPORTED via callgraph _alias_bare_names.
        "name": "py_aliased_import", "lang": "python",
        "desc": "from yaml import load as L; L(s) — symbol-aliased import, now resolved",
        "ecosystem": "pypi", "library": "PyYAML", "version": "5.1",
        "sink_symbols": ["yaml.load", "load"], "expected_reachable": True, "dep_type": "direct",
        "files": {
            "requirements.txt": "PyYAML==5.1\n",
            "app.py": "from yaml import load as L\n\ndef parse(s):\n    return L(s)  # vulnerable, aliased\n",
        },
    },
    {
        "name": "js_named_alias", "lang": "javascript",
        "desc": "import { defaultsDeep as dd } from 'lodash'; dd(...) — symbol-aliased, now resolved",
        "ecosystem": "npm", "library": "lodash", "version": "4.17.4",
        "sink_symbols": ["defaultsDeep"], "expected_reachable": True, "dep_type": "direct",
        "files": {
            "package.json": '{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.4"}}\n',
            "index.js": "import { defaultsDeep as dd } from 'lodash';\nfunction build(x){ return dd({}, x); }\nexport default build;\n",
        },
    },
]


# ---------------------------------------------------------------------------
# Known-gap cases — patterns the STATIC CORE misses today (reported separately,
# NOT counted in headline metrics). Honesty over cherry-picking; each maps to a
# documented ROADMAP item. The full pipeline's LLM layer may recover some of these.
# ---------------------------------------------------------------------------
KNOWN_GAP_CASES = [
    {
        "name": "py_var_indirection", "lang": "python",
        "desc": "fn = yaml.load; fn(s) — call through a variable; needs data-flow, not just call-name match",
        "roadmap": "variable/data-flow aliasing (callgraph)",
        "sink_symbols": ["yaml.load", "load"], "expected_reachable": True,
        "files": {
            "app.py": "import yaml\n\ndef parse(s):\n    fn = yaml.load\n    return fn(s)  # vulnerable via indirection\n",
        },
    },
]


def _materialize(case: dict, root: Path) -> Path:
    d = root / case["name"]
    d.mkdir(parents=True, exist_ok=True)
    for rel, content in case["files"].items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, "utf-8")
    return d


def _is_reachable(case_dir: Path, sink_symbols: list) -> bool:
    """Deterministic: does the tree-sitter call graph find a path to the vulnerable
    symbol in ANY source file of the project?"""
    for f in case_dir.rglob("*"):
        if f.is_file() and f.suffix in SRC_EXTS:
            try:
                res = build_reachability_paths(case_dir, f, sink_symbols)
            except Exception:
                res = None
            if res and res.get("paths"):
                return True
    return False


def _detected(case: dict, case_dir: Path) -> bool:
    """For transitive cases: confirm the resolver surfaces the transitive lib from the lockfile."""
    direct = case.get("direct")
    if not direct:
        return True
    manifest = "package.json" if case["ecosystem"] == "npm" else "requirements.txt"
    seed = [{"ecosystem": case["ecosystem"], "file": str(case_dir / manifest),
             "library": direct["library"], "version": direct["version"]}]
    resolved = resolve_transitive_deps(seed)
    return any(d["library"] == case["library"] for d in resolved)


def main():
    tp = fp = fn = tn = 0
    detect_ok = detect_total = 0
    results = []

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for case in CASES:
            cdir = _materialize(case, root)
            predicted = _is_reachable(cdir, case["sink_symbols"])
            expected = case["expected_reachable"]

            if case.get("dep_type") == "transitive":
                detect_total += 1
                if _detected(case, cdir):
                    detect_ok += 1

            if predicted and expected:
                tp += 1; verdict = "TP"
            elif predicted and not expected:
                fp += 1; verdict = "FP"
            elif not predicted and expected:
                fn += 1; verdict = "FN"
            else:
                tn += 1; verdict = "TN"
            results.append((case["name"], case["lang"], expected, predicted, verdict))

        # known gaps — informational only
        gap_results = []
        for case in KNOWN_GAP_CASES:
            cdir = _materialize(case, root)
            predicted = _is_reachable(cdir, case["sink_symbols"])
            gap_results.append((case["name"], predicted, case["expected_reachable"], case["roadmap"]))

    n = len(CASES)
    real = tp + fn
    latent = tn + fp
    recall = tp / real if real else 1.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    fp_reduction = tn / latent if latent else 0.0
    naive_precision = real / n if n else 0.0

    print("=" * 80)
    print("DEMENTOR REACHABILITY BENCHMARK  (deterministic, offline — call graph only)")
    print("=" * 80)
    print(f"{'case':<26} {'lang':<11} {'expected':<9} {'predicted':<10} {'verdict'}")
    print("-" * 80)
    for name, lang, exp, pred, verdict in results:
        mark = "ok " if verdict in ("TP", "TN") else "MISS"
        print(f"{name:<26} {lang:<11} {str(exp):<9} {str(pred):<10} {verdict:<4} {mark}")
    print("-" * 80)
    langs = sorted({lang for _, lang, *_ in results})
    print(f"Cases: {n}   languages: {', '.join(langs)}   (reachable: {real}, latent: {latent})")
    print(f"Confusion:  TP={tp}  TN={tn}  FP={fp}  FN={fn}")
    print()
    print(f"  Reachability recall    : {recall:6.1%}   (real vulns correctly confirmed reachable)")
    print(f"  Reachability precision : {precision:6.1%}   (flagged-reachable that are truly reachable)")
    print(f"  Naive SCA precision    : {naive_precision:6.1%}   (flags everything present)")
    print(f"  Dementor precision     : {precision:6.1%}")
    print(f"  False-positive cut     : {fp_reduction:6.1%}   ({tn}/{latent} latent findings suppressed)")
    if detect_total:
        print(f"  Transitive detection   : {detect_ok}/{detect_total} transitive libs surfaced from lockfiles")

    if gap_results:
        print()
        print("Known limitations (static core; NOT in headline — see ROADMAP):")
        for name, pred, exp, roadmap in gap_results:
            status = "caught" if pred == exp else "MISSED (expected — documented gap)"
            print(f"  {name:<24} reachable={str(pred):<6} {status}  [{roadmap}]")
    print("=" * 80)

    ok = (fn == 0 and fp == 0)
    print("RESULT:", "PERFECT separation on supported set ✅" if ok
          else f"{fn} miss(es) + {fp} false alarm(s) on supported set ⚠️")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
