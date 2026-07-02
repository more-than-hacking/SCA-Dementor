"""Tests for AI flow tracing — grounding / anti-hallucination guard.

The LLM may only use functions present in the provided real source; any node it
returns that isn't a provided function is dropped, and a path that doesn't end at
the sink is rejected (falls back to the tree-sitter ground truth).

Run standalone:  python tests/test_flow_trace.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dementor_sca.reachability_scan as rs

_CAND = {
    "sink_function": "bind", "sink_file": "B.java", "sink_symbol": "load",
    "candidates": [
        {"function": "bind", "file": "B.java", "line": 2, "source": "void bind(String d){ Yaml.load(d); }"},
        {"function": "updateUser", "file": "U.java", "line": 2, "source": "void updateUser(){ new B().bind(x); }"},
    ],
}


def _with_llm(reply, fn):
    orig = rs._llm_chat
    rs._llm_chat = lambda prompt: reply
    try:
        return fn()
    finally:
        rs._llm_chat = orig


def test_valid_path_accepted():
    reply = '{"paths":[[{"function":"updateUser","file":"U.java"},{"function":"bind","file":"B.java"}]]}'
    res = _with_llm(reply, lambda: rs.trace_reachability_flow_llm(_CAND))
    assert res["ai_verified"] is True
    fns = [n["function"] for n in res["paths"][0]]
    assert fns == ["updateUser", "bind"]
    assert res["paths"][0][-1]["is_sink"] is True


def test_hallucinated_node_dropped():
    # GHOST is not a provided function → must be removed; path still valid (ends at sink).
    reply = ('{"paths":[[{"function":"updateUser","file":"U.java"},'
             '{"function":"GHOST","file":"X.java"},{"function":"bind","file":"B.java"}]]}')
    res = _with_llm(reply, lambda: rs.trace_reachability_flow_llm(_CAND))
    fns = [n["function"] for p in res["paths"] for n in p]
    assert "GHOST" not in fns
    assert res["paths"][0][-1]["function"] == "bind"


def test_path_not_ending_at_sink_rejected():
    # Path doesn't reach the sink → rejected → falls back to sink-only ground truth.
    reply = '{"paths":[[{"function":"updateUser","file":"U.java"}]]}'
    res = _with_llm(reply, lambda: rs.trace_reachability_flow_llm(_CAND))
    assert res["ai_verified"] is False
    assert res["paths"] == [[{"function": "bind", "file": "B.java", "line": 0, "is_sink": True}]]


def test_garbage_llm_output_falls_back():
    res = _with_llm("sorry, I cannot help", lambda: rs.trace_reachability_flow_llm(_CAND))
    assert res["ai_verified"] is False
    assert res["paths"][0][0]["is_sink"] is True


def test_single_candidate_skips_llm():
    one = {"sink_function": "bind", "sink_file": "B.java", "sink_symbol": "load",
           "candidates": [{"function": "bind", "file": "B.java", "line": 2, "source": "x"}]}
    # Should not even call the LLM; returns ground-truth sink only.
    res = _with_llm("SHOULD NOT BE USED", lambda: rs.trace_reachability_flow_llm(one))
    assert res["ai_verified"] is False and len(res["paths"][0]) == 1


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t(); print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1; print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
