"""Tests for cross-file call-graph slicing (dementor_sca.callgraph).

Verifies that a vulnerable sink in one file is correctly linked back to the caller
in another file where untrusted input enters — the cross-file dataflow case that
single-file LLM analysis can't see.

Run standalone:  python tests/test_callgraph.py
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dementor_sca import callgraph
from dementor_sca.callgraph import build_caller_slice, TREE_SITTER_AVAILABLE


def _mkrepo(files: dict) -> Path:
    repo = Path(tempfile.mkdtemp())
    for name, content in files.items():
        (repo / name).write_text(content)
    # Reset the index cache so each repo is freshly indexed.
    callgraph._INDEX_CACHE.clear()
    return repo


def test_tree_sitter_available():
    # If this fails, `pip install tree-sitter tree-sitter-python`.
    assert TREE_SITTER_AVAILABLE, "tree-sitter not installed"


def test_cross_file_caller_traced():
    repo = _mkrepo({
        "handler.py": "import yaml\ndef handle(data):\n    return yaml.load(data)\n",
        "router.py": "from handler import handle\ndef route(request):\n    body = request.body\n    return handle(body)\n",
        "noise.py": "def helper():\n    return 42\n",
    })
    s = build_caller_slice(repo, repo / "handler.py", ["yaml.load", "load"])
    assert s is not None
    assert s.sink_function == "handle"
    assert s.sink_in_parameter is True          # data is a parameter → external taint
    assert s.caller_count >= 1
    names = {Path(f).name for f in s.files_involved}
    assert {"handler.py", "router.py"} <= names
    assert "noise.py" not in names              # unrelated file excluded
    assert "request.body" in s.slice_text       # the source line is in the slice


def test_sink_uses_local_constant_not_parameter():
    # Sink argument is a local literal, not a parameter → not externally tainted.
    repo = _mkrepo({
        "safe.py": "import yaml\ndef load_config():\n    text = '{a: 1}'\n    return yaml.load(text)\n",
    })
    s = build_caller_slice(repo, repo / "safe.py", ["yaml.load", "load"])
    assert s is not None
    assert s.sink_function == "load_config"
    assert s.sink_in_parameter is False


def test_no_sink_returns_none():
    repo = _mkrepo({"x.py": "import yaml\ndef f():\n    return yaml.safe_load('{}')\n"})
    # Looking for 'load' should not match 'safe_load' (different trailing identifier).
    s = build_caller_slice(repo, repo / "x.py", ["yaml.load"])
    assert s is None


def test_non_python_file_returns_none():
    repo = _mkrepo({"Dockerfile": "RUN gunicorn app:app\n"})
    assert build_caller_slice(repo, repo / "Dockerfile", ["gunicorn"]) is None


def test_java_cross_file_caller_traced():
    if "java" not in callgraph.SUPPORTED_LANGUAGES:
        return  # grammar not installed — skip
    repo = _mkrepo({
        "Handler.java": "class Handler {\n  String handle(String data) { return Yaml.load(data); }\n}\n",
        "Controller.java": "class Controller {\n  void route(Request req) { new Handler().handle(req.getBody()); }\n}\n",
    })
    s = build_caller_slice(repo, repo / "Handler.java", ["Yaml.load", "load"])
    assert s is not None
    assert s.sink_function == "handle"
    assert s.sink_in_parameter is True
    assert s.caller_count >= 1
    assert {"Handler.java", "Controller.java"} <= {Path(f).name for f in s.files_involved}


def test_go_sink_detected():
    if "go" not in callgraph.SUPPORTED_LANGUAGES:
        return
    repo = _mkrepo({
        "handler.go": "package m\nfunc Handle(d string) string { return yaml.Load(d) }\n",
        "router.go": "package m\nfunc Route(r Req) { Handle(r.Body) }\n",
    })
    s = build_caller_slice(repo, repo / "handler.go", ["yaml.Load", "Load"])
    assert s is not None
    assert s.sink_function == "Handle"
    assert s.caller_count >= 1


def test_test_code_excluded_from_index():
    # A sink called only from test code must NOT pull test methods into the graph.
    repo = _mkrepo({
        "Service.java": "class Service {\n  void run(String d) { Yaml.load(d); }\n}\n",
        "ServiceTest.java": "class ServiceTest {\n  void testRun() { new Service().run(\"x\"); }\n}\n",
    })
    g = callgraph.export_graph(repo, focus_symbols=["Yaml.load", "load"], paths_only=True)
    labels = {n["label"] for n in g["nodes"]}
    assert "testRun" not in labels          # test method excluded
    assert "run" in labels                  # production sink kept


def test_generic_object_methods_not_matched():
    # CVE symbol "ClassUtils.getClass" must NOT flag Object.getClass() inside equals().
    from dementor_sca.callgraph import _matchable_sink_names
    assert _matchable_sink_names(["ClassUtils.getClass", "org.apache.commons", "equals"]) == set()
    assert _matchable_sink_names(["yaml.load", "readObject"]) == {"load", "readObject"}


def test_equals_getclass_false_positive_suppressed():
    repo = _mkrepo({
        "Vendor.java": "class Vendor {\n  public boolean equals(Object o) { return getClass() == o.getClass(); }\n}\n",
    })
    # commons-lang3 CVE symbol — must not flag the equals()/getClass() pattern.
    res = callgraph.build_reachability_paths(repo, repo / "Vendor.java",
                                             ["ClassUtils.getClass", "org.apache.commons"])
    assert res is None, "generic getClass must not produce a sink"


def test_qualified_generic_method_matched():
    # ClassUtils.getClass (qualified) must match; bare Object.getClass() must not.
    from dementor_sca.callgraph import _sink_matchers
    bare, qual = _sink_matchers(["ClassUtils.getClass", "org.apache.commons"])
    assert bare == set() and qual == {"classutils.getclass"}

    repo = _mkrepo({"Loader.java": "class Loader {\n  Object load(String n){ return ClassUtils.getClass(n); }\n}\n"})
    res = callgraph.build_reachability_paths(repo, repo / "Loader.java", ["ClassUtils.getClass"])
    assert res is not None and res["sink_function"] == "load"

    repo2 = _mkrepo({"Vendor.java": "class Vendor {\n  public boolean equals(Object o){ return getClass() == o.getClass(); }\n}\n"})
    assert callgraph.build_reachability_paths(repo2, repo2 / "Vendor.java", ["ClassUtils.getClass"]) is None


def test_java_export_graph():
    if "java" not in callgraph.SUPPORTED_LANGUAGES:
        return
    repo = _mkrepo({
        "Handler.java": "class Handler {\n  String handle(String data) { return Yaml.load(data); }\n}\n",
        "Controller.java": "class Controller {\n  void route(Request req) { new Handler().handle(req.getBody()); }\n}\n",
    })
    g = callgraph.export_graph(repo, focus_symbols=["Yaml.load", "load"])
    assert g["available"]
    kinds = {n["label"]: n["kind"] for n in g["nodes"]}
    assert kinds.get("handle") == "sink"          # handle() calls Yaml.load
    assert g["stats"]["sinks"] >= 1
    assert "java" in g["stats"]["languages"]


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
