"""Tests for transitive dependency resolution (dementor_sca.transitive_resolver).

Manifest parsers only see DIRECT deps; most CVEs live in transitive ones. The resolver
reads adjacent lockfiles to expand the graph. These tests cover the lockfile formats we
support (npm v1/v2-3, Pipfile.lock), plus the invariants that matter for correctness:
direct deps preserved + tagged, transitive deps tagged, dedupe, and graceful no-lockfile.

Run standalone:  python tests/test_transitive_resolver.py
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dementor_sca.transitive_resolver import (
    resolve_transitive_deps, _parse_maven_tree, _parse_go_list,
)


def _write(d: Path, name: str, content) -> Path:
    p = d / name
    p.write_text(content if isinstance(content, str) else json.dumps(content), "utf-8")
    return p


def test_npm_v3_packages_map_adds_transitive():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        _write(d, "package-lock.json", {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/express": {"version": "4.18.0"},
                "node_modules/basic-ftp": {"version": "5.0.5"},          # transitive
                "node_modules/@scope/util": {"version": "2.1.0"},        # scoped transitive
                "node_modules/express/node_modules/cookie": {"version": "0.5.0"},  # nested
            },
        })
        direct = [{"ecosystem": "npm", "file": str(d / "package.json"),
                   "library": "express", "version": "4.18.0"}]
        out = resolve_transitive_deps(direct)
        by_name = {(o["library"], o["version"]): o for o in out}

        assert by_name[("express", "4.18.0")]["dep_type"] == "direct"
        assert by_name[("basic-ftp", "5.0.5")]["dep_type"] == "transitive"
        assert by_name[("@scope/util", "2.1.0")]["dep_type"] == "transitive"   # scope preserved
        assert by_name[("cookie", "0.5.0")]["dep_type"] == "transitive"        # nested path name
        # transitive deps carry the lockfile + inherit the manifest file
        assert by_name[("basic-ftp", "5.0.5")]["lockfile"].endswith("package-lock.json")
        assert by_name[("basic-ftp", "5.0.5")]["file"].endswith("package.json")


def test_npm_v1_nested_dependencies():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        _write(d, "package-lock.json", {
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {"version": "4.17.21"},
                "request": {"version": "2.88.2",
                            "dependencies": {"tough-cookie": {"version": "2.5.0"}}},
            },
        })
        direct = [{"ecosystem": "npm", "file": str(d / "package.json"),
                   "library": "request", "version": "2.88.2"}]
        out = resolve_transitive_deps(direct)
        names = {o["library"] for o in out}
        assert {"request", "lodash", "tough-cookie"} <= names
        by_name = {o["library"]: o for o in out}
        assert by_name["request"]["dep_type"] == "direct"
        assert by_name["tough-cookie"]["dep_type"] == "transitive"  # nested


def test_pipfile_lock_default_and_develop():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        _write(d, "Pipfile.lock", {
            "default": {"requests": {"version": "==2.28.0"},
                        "urllib3": {"version": "==1.26.7"}},   # transitive
            "develop": {"pytest": {"version": "==7.0.0"}},
        })
        direct = [{"ecosystem": "pypi", "file": str(d / "requirements.txt"),
                   "library": "requests", "version": "2.28.0"}]
        out = resolve_transitive_deps(direct)
        by_name = {o["library"]: o for o in out}
        assert by_name["requests"]["dep_type"] == "direct"
        assert by_name["urllib3"]["version"] == "1.26.7"        # "==" stripped
        assert by_name["urllib3"]["dep_type"] == "transitive"
        assert by_name["pytest"].get("dev") is True             # develop section flagged


def test_direct_dep_never_overridden_and_no_dupes():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        _write(d, "package-lock.json", {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app"},
                "node_modules/express": {"version": "4.18.0"},  # same as the direct dep
            },
        })
        direct = [{"ecosystem": "npm", "file": str(d / "package.json"),
                   "library": "express", "version": "4.18.0", "dep_type": "direct"}]
        out = resolve_transitive_deps(direct)
        express = [o for o in out if o["library"] == "express"]
        assert len(express) == 1                       # not duplicated
        assert express[0]["dep_type"] == "direct"      # stays direct


def test_graceful_when_no_lockfile():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        direct = [{"ecosystem": "npm", "file": str(d / "package.json"),
                   "library": "express", "version": "4.18.0"}]
        out = resolve_transitive_deps(direct)
        assert len(out) == 1                           # unchanged, no crash
        assert out[0]["dep_type"] == "direct"          # still tagged


def test_empty_input():
    assert resolve_transitive_deps([]) == []


def test_parse_maven_tree():
    out = (
        "[INFO] com.example:app:jar:1.0.0\n"
        "[INFO] +- org.yaml:snakeyaml:jar:1.30:compile\n"
        "[INFO] |  \\- com.foo:bar:jar:2.0:compile\n"
        "[INFO] \\- com.fasterxml.jackson.core:jackson-databind:jar:2.13.0:compile\n"
    )
    libs = {lib: ver for (lib, ver, _, _) in _parse_maven_tree(out)}
    assert libs.get("org.yaml:snakeyaml") == "1.30"
    assert libs.get("com.foo:bar") == "2.0"
    assert libs.get("com.fasterxml.jackson.core:jackson-databind") == "2.13.0"
    assert "com.example:app" not in libs            # root project (no tree connector) skipped


def test_parse_go_list():
    out = ("example.com/app\n"
           "github.com/foo/bar v1.2.3\n"
           "gopkg.in/yaml.v2 v2.2.2\n"
           "golang.org/x/text v0.3.0 => golang.org/x/text v0.3.7\n")
    libs = {mod: ver for (mod, ver, _, _) in _parse_go_list(out)}
    assert libs.get("gopkg.in/yaml.v2") == "v2.2.2"
    assert libs.get("github.com/foo/bar") == "v1.2.3"
    assert libs.get("golang.org/x/text") == "v0.3.7"   # replace (=>) takes the effective version
    assert "example.com/app" not in libs               # main module (no version) skipped


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
