"""Tests for dynamic rate-limit backoff (llm_client._call_with_backoff).

Free-tier LLMs (e.g. Gemini) rate-limit parallel reachability calls (429). Calls should retry
with backoff instead of failing the finding; non-retryable errors should surface immediately.

Run standalone:  python tests/test_llm_backoff.py
"""
import os
import sys
from pathlib import Path

# Fast, deterministic backoff for the test.
os.environ["LLM_BACKOFF_BASE"] = "0"
os.environ["LLM_BACKOFF_MAX"] = "0"
os.environ["LLM_MAX_RETRIES"] = "4"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests
from dementor_sca import llm_client


def _http_error(status, headers=None):
    e = requests.HTTPError(f"{status} error")
    class _R:
        status_code = status
    r = _R()
    r.headers = headers or {}
    e.response = r
    return e


def test_retries_then_succeeds_on_429():
    calls = {"n": 0}
    def call():
        calls["n"] += 1
        if calls["n"] < 3:
            raise _http_error(429)
        return "OK"
    assert llm_client._call_with_backoff(call) == "OK"
    assert calls["n"] == 3


def test_non_retryable_4xx_raises_immediately():
    calls = {"n": 0}
    def call():
        calls["n"] += 1
        raise _http_error(400)
    try:
        llm_client._call_with_backoff(call)
        assert False, "should have raised"
    except requests.HTTPError:
        pass
    assert calls["n"] == 1   # no retries on a 400


def test_gives_up_after_max_retries():
    calls = {"n": 0}
    def call():
        calls["n"] += 1
        raise _http_error(429)
    try:
        llm_client._call_with_backoff(call)
        assert False
    except requests.HTTPError:
        pass
    assert calls["n"] == 5   # 1 + LLM_MAX_RETRIES(4)


def test_quota_message_is_retryable():
    calls = {"n": 0}
    def call():
        calls["n"] += 1
        if calls["n"] < 2:
            raise RuntimeError("RESOURCE_EXHAUSTED: quota exceeded")
        return "ok"
    assert llm_client._call_with_backoff(call) == "ok"


def test_honors_retry_after_header():
    calls = {"n": 0}
    def call():
        calls["n"] += 1
        if calls["n"] < 2:
            raise _http_error(429, {"Retry-After": "0"})
        return "ok"
    assert llm_client._call_with_backoff(call) == "ok"


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
