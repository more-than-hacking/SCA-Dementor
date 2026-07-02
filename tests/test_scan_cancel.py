"""Tests for cooperative scan cancellation (Stop-scan button).

A running scan must stop on request: scan_runner tracks a per-job cancel flag, and the
reachability phase stops dispatching new work when should_cancel() returns True. In-flight
LLM calls finish (threads can't be force-killed) — so the stop is cooperative, not a kill.

Run standalone:  python tests/test_scan_cancel.py
"""
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dementor_sca import scan_runner
from dementor_sca import pipeline_zero_fp as P


# ── scan_runner cancel registry ────────────────────────────────────────────────
def test_request_cancel_sets_flag_for_running_job():
    jid = "test-job-running"
    with scan_runner._JOBS_LOCK:
        scan_runner._JOBS[jid] = {"job_id": jid, "status": "running",
                                  "cancel_event": threading.Event()}
    try:
        assert scan_runner._is_cancelled(jid) is False
        assert scan_runner.request_cancel(jid) is True
        assert scan_runner._is_cancelled(jid) is True
    finally:
        with scan_runner._JOBS_LOCK:
            scan_runner._JOBS.pop(jid, None)


def test_request_cancel_returns_false_for_finished_job():
    jid = "test-job-done"
    with scan_runner._JOBS_LOCK:
        scan_runner._JOBS[jid] = {"job_id": jid, "status": "done",
                                  "cancel_event": threading.Event()}
    try:
        assert scan_runner.request_cancel(jid) is False
    finally:
        with scan_runner._JOBS_LOCK:
            scan_runner._JOBS.pop(jid, None)


def test_request_cancel_unknown_job_is_false():
    assert scan_runner.request_cancel("no-such-job") is False


# ── reachability phase honors should_cancel ────────────────────────────────────
def test_phase3_stops_dispatching_when_cancelled(monkeypatch=None):
    """With one worker, processing stops as soon as should_cancel() flips to True."""
    seen = []

    def fake_entry(entry, token, org, ai_refine=True):
        seen.append(entry["library"])
        return entry

    orig = P._reachability_for_entry
    P._reachability_for_entry = fake_entry
    # Force serial mode so order is deterministic.
    import os
    os.environ["REACHABILITY_WORKERS"] = "1"
    try:
        entries = [{"library": f"lib{i}", "file_location": ""} for i in range(5)]
        # Cancel after the first entry is processed.
        state = {"calls": 0}
        def should_cancel():
            state["calls"] += 1
            return len(seen) >= 1   # stop once we've processed one
        out = P.run_phase3_reachability(entries, "tok", "org", should_cancel=should_cancel)
        assert len(seen) == 1, f"expected to stop after 1, processed {seen}"
        assert len(out) == 1
    finally:
        P._reachability_for_entry = orig
        os.environ.pop("REACHABILITY_WORKERS", None)


def test_phase3_processes_all_when_not_cancelled():
    seen = []
    def fake_entry(entry, token, org, ai_refine=True):
        seen.append(entry["library"]); return entry
    orig = P._reachability_for_entry
    P._reachability_for_entry = fake_entry
    import os
    os.environ["REACHABILITY_WORKERS"] = "1"
    try:
        entries = [{"library": f"lib{i}", "file_location": ""} for i in range(4)]
        out = P.run_phase3_reachability(entries, "tok", "org", should_cancel=lambda: False)
        assert len(out) == 4 and len(seen) == 4
    finally:
        P._reachability_for_entry = orig
        os.environ.pop("REACHABILITY_WORKERS", None)


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
