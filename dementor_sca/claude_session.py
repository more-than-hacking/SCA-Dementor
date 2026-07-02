"""Claude CLI session management — in-pod auth via Claude subscription.

Runs the local `claude` binary (`claude -p`) using your Claude subscription, so
the AI reachability analysis costs no per-token API spend. Authenticate once with
the Authenticate button (PTY-driven `claude auth login`); the session is stored in
a CLAUDE_CONFIG_DIR under the project data dir so it survives across requests and,
in a pod, across restarts (mount that dir on a volume).

Simplified to single-tenant (Dementor has no per-user login).
"""
from __future__ import annotations

import json
import logging
import os
import subprocess as _subprocess
import time

from dementor_sca import REPO_ROOT

log = logging.getLogger(__name__)

CLAUDE_BIN = os.getenv("CLAUDE_CLI_BIN", "claude")
# Single-tenant: by default reuse the ambient `claude` login (~/.claude), so it
# "just works" if you're already signed in. Set CLAUDE_CONFIG_DIR to pin a
# dedicated session dir — recommended in k8s: mount it on a volume so the login
# survives pod restarts.
_SESSION_DIR = os.getenv("CLAUDE_CONFIG_DIR", "").strip() or None
if _SESSION_DIR:
    os.makedirs(_SESSION_DIR, exist_ok=True)

# Live PTY login process + its master fd, kept between /auth and /auth/code calls.
_auth_proc: _subprocess.Popen | None = None
_auth_fd: int | None = None


def claude_env() -> dict:
    """Environment for shelling out to `claude` — strips the nested-session guard
    and pins the config dir to our shared session."""
    env = {**os.environ}
    for k in ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_EXECPATH"):
        env.pop(k, None)
    if _SESSION_DIR:
        env["CLAUDE_CONFIG_DIR"] = _SESSION_DIR
    return env


def status() -> dict:
    """Run `claude auth status --json`. Returns the CLI's status dict, augmented
    with an `available` flag (False if the binary is missing)."""
    try:
        r = _subprocess.run(
            [CLAUDE_BIN, "auth", "status", "--json"],
            capture_output=True, text=True, timeout=10, env=claude_env(),
        )
        if r.returncode == 0 and r.stdout.strip():
            data = json.loads(r.stdout)
            data["available"] = True
            return data
        return {"available": True, "loggedIn": False,
                "error": (r.stderr or r.stdout or "").strip()[:200]}
    except FileNotFoundError:
        return {"available": False, "loggedIn": False,
                "error": f"`{CLAUDE_BIN}` not found on PATH"}
    except _subprocess.TimeoutExpired:
        return {"available": True, "loggedIn": False,
                "error": "auth status timed out (pod may not reach claude.ai)"}
    except Exception as e:  # pragma: no cover - defensive
        return {"available": True, "loggedIn": False, "error": str(e)}


def is_authenticated() -> bool:
    return bool(status().get("loggedIn"))


def start_auth() -> str:
    """Launch `claude auth login` under a PTY and capture the OAuth URL it prints.
    Returns the URL (empty string if none was captured within the timeout)."""
    import pty
    import select

    global _auth_proc, _auth_fd

    # Kill any stale login process.
    if _auth_proc is not None:
        try:
            _auth_proc.kill()
        except Exception:
            pass
        _auth_proc = None
    if _auth_fd is not None:
        try:
            os.close(_auth_fd)
        except OSError:
            pass
        _auth_fd = None

    master_fd, slave_fd = pty.openpty()
    proc = _subprocess.Popen(
        [CLAUDE_BIN, "auth", "login"],
        stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
        env=claude_env(), close_fds=True,
    )
    os.close(slave_fd)
    _auth_proc = proc
    _auth_fd = master_fd

    auth_url = ""
    output = ""
    start_t = time.time()
    while time.time() - start_t < 25:
        ready, _, _ = select.select([master_fd], [], [], 1.0)
        if ready:
            try:
                chunk = os.read(master_fd, 4096).decode("utf-8", errors="ignore")
            except OSError:
                break
            output += chunk
            for line in output.split("\n"):
                if "claude.ai/oauth" in line or "claude.com/cai/oauth" in line or "console.anthropic.com" in line:
                    for part in line.split():
                        if part.startswith("http"):
                            auth_url = part.strip()
                            break
                if auth_url:
                    break
            if auth_url:
                break
        if proc.poll() is not None:
            break

    if not auth_url:
        log.warning("Claude auth: no URL captured from login output")
    else:
        log.info("Claude auth: OAuth URL captured")
    return auth_url


def submit_code(code: str) -> bool:
    """Write the pasted authorization code into the live PTY login process and
    wait for it to complete. Returns True if authenticated afterwards."""
    import select

    global _auth_proc, _auth_fd
    proc, master_fd = _auth_proc, _auth_fd
    if proc is None or master_fd is None:
        log.warning("Claude auth: submit_code called with no live login process")
        return False

    try:
        os.write(master_fd, (code.strip() + "\n").encode())
        pty_output = ""
        for _ in range(30):
            ready, _, _ = select.select([master_fd], [], [], 1.0)
            if ready:
                try:
                    pty_output += os.read(master_fd, 4096).decode("utf-8", errors="ignore")
                except OSError:
                    break
            if proc.poll() is not None:
                break

        ok = proc.poll() is not None and proc.returncode == 0
        if not ok:
            # Process may stay alive briefly; fall back to a real status check.
            ok = is_authenticated()
        return ok
    except Exception:
        log.error("Claude auth: error submitting code", exc_info=True)
        return False
    finally:
        try:
            if master_fd is not None:
                os.close(master_fd)
        except OSError:
            pass
        _auth_proc = None
        _auth_fd = None


def call(prompt: str, timeout: int = 120, model: str = None) -> str:
    """Run a prompt through `claude -p` and return the text reply.
    `model` (e.g. claude-haiku-4-5-…) is passed to the CLI — without it the CLI uses its
    default model, which can be far more expensive (Opus)."""
    cmd = [CLAUDE_BIN, "-p", "--output-format", "json"]
    if model:
        cmd += ["--model", model]
    try:
        r = _subprocess.run(
            cmd, input=prompt, capture_output=True, text=True, timeout=timeout, env=claude_env(),
        )
        if r.returncode != 0:
            # Retry as plain text output (older CLIs / odd states).
            retry = [CLAUDE_BIN, "-p"] + (["--model", model] if model else [])
            r = _subprocess.run(
                retry, input=prompt, capture_output=True, text=True, timeout=timeout, env=claude_env(),
            )
        stdout = (r.stdout or "").strip()
        if r.returncode != 0:
            raise RuntimeError((r.stderr or stdout or "claude CLI failed").strip()[:300])
        try:
            parsed = json.loads(stdout)
            if isinstance(parsed, dict):
                # Record token usage + cost (the CLI reports both in --output-format json).
                u = parsed.get("usage") or {}
                try:
                    from dementor_sca import llm_client
                    llm_client.record_usage(
                        # fold cache-creation into "input" so the count reflects real input processed
                        input_tokens=u.get("input_tokens", 0) + u.get("cache_creation_input_tokens", 0),
                        output_tokens=u.get("output_tokens", 0),
                        cache_read_tokens=u.get("cache_read_input_tokens", 0),
                        cost_usd=parsed.get("total_cost_usd", 0.0),
                    )
                except Exception:
                    pass
                if "result" in parsed:
                    return parsed["result"]
        except (json.JSONDecodeError, TypeError):
            pass
        return stdout
    except FileNotFoundError:
        raise RuntimeError(f"`{CLAUDE_BIN}` not found on PATH — install the Claude CLI in this environment.")


def test() -> dict:
    """Quick connectivity check used by the Test button. {ok, message, latency_ms}."""
    start = time.time()
    st = status()
    if not st.get("available"):
        return {"ok": False, "message": st.get("error", "Claude CLI not installed"),
                "latency_ms": round((time.time() - start) * 1000)}
    if not st.get("loggedIn"):
        return {"ok": False, "message": "Not authenticated — click Authenticate to sign in",
                "latency_ms": round((time.time() - start) * 1000)}
    try:
        reply = call("Reply with exactly: OK", timeout=30)
    except Exception as e:
        return {"ok": False, "message": str(e)[:200],
                "latency_ms": round((time.time() - start) * 1000)}
    latency = round((time.time() - start) * 1000)
    if reply and reply.strip():
        email = st.get("email", "")
        who = f" as {email}" if email else ""
        return {"ok": True, "message": f"Connected{who} — Claude responded", "latency_ms": latency}
    return {"ok": False, "message": "Empty response (possible rate limit or expired session)",
            "latency_ms": latency}
