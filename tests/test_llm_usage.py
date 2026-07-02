"""Tests for LLM token/cost tracking (llm_client usage recording + cost estimation).

APIs (Gemini/OpenAI/Anthropic) return token counts but not cost, so Dementor estimates cost from
a per-model price table and records it — surfacing a real "AI usage: N calls · X tok · ~$Y" figure
for Gemini scans (previously only the Claude CLI tracked usage).

Run standalone:  python tests/test_llm_usage.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dementor_sca import llm_client as L


def test_cost_estimation_known_models():
    assert round(L._estimate_cost("gemini-2.5-flash", 1_000_000, 1_000_000), 3) == 2.80   # 0.30 + 2.50
    assert round(L._estimate_cost("gemini-2.5-flash-lite", 1_000_000, 1_000_000), 3) == 0.50
    assert round(L._estimate_cost("gpt-4o-mini", 1_000_000, 0), 3) == 0.15


def test_cost_unknown_model_is_zero():
    assert L._estimate_cost("some-unknown-model", 1000, 1000) == 0.0


def test_records_openai_style_usage_with_cost():
    L.reset_usage()
    L._record_openai_usage({"usage": {"prompt_tokens": 10_000, "completion_tokens": 2_000}}, "gemini-2.5-flash")
    u = L.get_usage()
    assert u["calls"] == 1
    assert u["input_tokens"] == 10_000 and u["output_tokens"] == 2_000
    # 10000/1M*0.30 + 2000/1M*2.50 = 0.003 + 0.005 = 0.008
    assert round(u["cost_usd"], 4) == 0.008


def test_records_anthropic_style_usage():
    L.reset_usage()
    L._record_anthropic_usage({"usage": {"input_tokens": 1_000_000, "output_tokens": 0}}, "claude-3-5-haiku-20241022")
    u = L.get_usage()
    assert u["input_tokens"] == 1_000_000
    assert round(u["cost_usd"], 3) == 0.80


def test_no_usage_field_is_noop():
    L.reset_usage()
    L._record_openai_usage({"choices": [{"message": {"content": "hi"}}]}, "gemini-2.5-flash")
    assert L.get_usage()["calls"] == 0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  ok  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
