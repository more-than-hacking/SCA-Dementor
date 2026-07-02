# llm_client.py
"""
Multi-provider LLM client.

Supported providers (set via config/org_config.yaml  llm.provider  or  LLM_PROVIDER env var):

    cursor      — Cursor AI proxy (default, no key needed, Cursor IDE must be running)
                  URL: http://localhost:3000  (or CURSOR_PROXY_URL)
                  API: POST /api/chat  { message, history? }

    openai      — OpenAI Chat Completions API
                  URL: https://api.openai.com/v1  (or LLM_API_URL for Azure / compatible)
                  Key: LLM_API_KEY or org_config llm.api_key
                  Model: gpt-4o  (or LLM_MODEL / llm.model)

    anthropic   — Anthropic Messages API  (billed API key)
                  URL: https://api.anthropic.com  (or LLM_API_URL)
                  Key: LLM_API_KEY or org_config llm.api_key   (sk-ant-… API key)
                  Model: claude-3-5-sonnet-20241022  (or LLM_MODEL / llm.model)

    claude_cli  — Runs the local `claude` CLI in-pod via your Claude subscription
                  (`claude -p`). NO per-token API cost. Authenticate once with the
                  Authenticate button (or `claude auth login`); the pod reuses the
                  ~/.claude session. No API key needed.
                  Bin:   `claude` must be on PATH (set CLAUDE_CLI_BIN to override)
                  Model: claude-opus-4-6  (or LLM_MODEL / llm.model; aliases ok: opus/sonnet)

    gemini      — Google Gemini via its OpenAI-compatible endpoint  (billed API key)
                  URL: https://generativelanguage.googleapis.com/v1beta/openai
                  Key: LLM_API_KEY or org_config llm.api_key   (Google AI Studio key)
                  Model: gemini-2.5-flash  (or LLM_MODEL / llm.model)

    custom      — Any OpenAI-compatible endpoint (Ollama, LM Studio, vLLM, Together AI…)
                  URL: LLM_API_URL  (required)
                  Key: LLM_API_KEY  (optional, send as Bearer token)
                  Model: LLM_MODEL  (required)

Environment variables (all optional — override config file):
    LLM_PROVIDER        cursor | openai | anthropic | custom
    LLM_API_URL         Base URL for the provider
    LLM_API_KEY         API key / secret
    LLM_MODEL           Model name
    CURSOR_PROXY_URL    Cursor proxy URL (provider=cursor only)
"""
import logging
import os
import threading

import requests
import yaml

_TIMEOUT = 120  # seconds

# ── Token / cost usage tracking (cumulative since process start) ────────────────
_USAGE = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cost_usd": 0.0}
_USAGE_LOCK = threading.Lock()


def record_usage(input_tokens=0, output_tokens=0, cache_read_tokens=0, cost_usd=0.0):
    """Accumulate one LLM call's usage. Called by providers that expose token counts."""
    with _USAGE_LOCK:
        _USAGE["calls"] += 1
        _USAGE["input_tokens"] += int(input_tokens or 0)
        _USAGE["output_tokens"] += int(output_tokens or 0)
        _USAGE["cache_read_tokens"] += int(cache_read_tokens or 0)
        _USAGE["cost_usd"] += float(cost_usd or 0.0)


def get_usage() -> dict:
    """Snapshot of cumulative usage. Take two snapshots to measure a scan's delta."""
    with _USAGE_LOCK:
        return dict(_USAGE)


def reset_usage():
    with _USAGE_LOCK:
        for k in _USAGE:
            _USAGE[k] = 0.0 if k == "cost_usd" else 0


# Approximate USD per 1M tokens (input, output). APIs (Gemini/OpenAI/Anthropic) return token
# counts but NOT cost, so we estimate. UPDATE as providers change their pricing. Longest-prefix
# match wins; unknown models cost 0 (counts still tracked). Override base via LLM_PRICE_IN/OUT.
_PRICE_PER_M = {
    "gemini-2.5-flash-lite": (0.10, 0.40),
    "gemini-2.5-flash":      (0.30, 2.50),
    "gemini-2.5-pro":        (1.25, 10.00),
    "gemini-2.0-flash-lite": (0.075, 0.30),
    "gemini-2.0-flash":      (0.10, 0.40),
    "gemini-1.5-flash":      (0.075, 0.30),
    "gemini-1.5-pro":        (1.25, 5.00),
    "gpt-4o-mini":           (0.15, 0.60),
    "gpt-4o":                (2.50, 10.00),
    "claude-3-5-haiku":      (0.80, 4.00),
    "claude-3-5-sonnet":     (3.00, 15.00),
}


def _estimate_cost(model: str, in_tok: int, out_tok: int) -> float:
    """Estimate cost from token counts via _PRICE_PER_M (longest-prefix match). Env overrides:
    LLM_PRICE_IN / LLM_PRICE_OUT (USD per 1M)."""
    pin, pout = os.getenv("LLM_PRICE_IN"), os.getenv("LLM_PRICE_OUT")
    if pin is not None and pout is not None:
        try:
            return in_tok / 1e6 * float(pin) + out_tok / 1e6 * float(pout)
        except ValueError:
            pass
    m = (model or "").lower()
    price = None
    for k in sorted(_PRICE_PER_M, key=len, reverse=True):   # longest prefix first
        if m.startswith(k) or k in m:
            price = _PRICE_PER_M[k]
            break
    if not price:
        return 0.0
    return in_tok / 1e6 * price[0] + out_tok / 1e6 * price[1]


def _record_openai_usage(resp_json: dict, model: str):
    """Record usage from an OpenAI-compatible response (Gemini/OpenAI/custom)."""
    u = (resp_json or {}).get("usage") or {}
    pt, ct = int(u.get("prompt_tokens", 0) or 0), int(u.get("completion_tokens", 0) or 0)
    if pt or ct:
        record_usage(input_tokens=pt, output_tokens=ct, cost_usd=_estimate_cost(model, pt, ct))


def _record_anthropic_usage(resp_json: dict, model: str):
    u = (resp_json or {}).get("usage") or {}
    it, ot = int(u.get("input_tokens", 0) or 0), int(u.get("output_tokens", 0) or 0)
    if it or ot:
        record_usage(input_tokens=it, output_tokens=ot, cost_usd=_estimate_cost(model, it, ot))

# ── Default model names per provider ──────────────────────────────────────────
_DEFAULT_MODELS = {
    "openai":     "gpt-4o",
    "anthropic":  "claude-3-5-sonnet-20241022",
    "claude_cli": "claude-opus-4-6",
    "gemini":     "gemini-2.5-flash",
    "cursor":     "cursor-proxy",
    "custom":     "default",
}

# ── Config cache ───────────────────────────────────────────────────────────────
_llm_config_cache: dict | None = None


def _load_llm_config() -> dict:
    """Read llm.* section from org_config.yaml (cached per process)."""
    global _llm_config_cache
    if _llm_config_cache is not None:
        return _llm_config_cache
    try:
        from dementor_sca import REPO_ROOT
        cfg_path = REPO_ROOT / "config" / "org_config.yaml"
        if cfg_path.exists():
            with open(cfg_path) as f:
                raw = yaml.safe_load(f) or {}
            _llm_config_cache = raw.get("llm", {}) or {}
        else:
            _llm_config_cache = {}
    except Exception:
        _llm_config_cache = {}
    return _llm_config_cache


def _cfg(key: str, default: str = "") -> str:
    """Return env-var override first, then org_config.yaml llm.* field, then default."""
    env_map = {
        "provider": "LLM_PROVIDER",
        "api_url":  "LLM_API_URL",
        "api_key":  "LLM_API_KEY",
        "model":    "LLM_MODEL",
    }
    env_val = os.getenv(env_map.get(key, ""), "").strip()
    if env_val:
        return env_val
    return str(_load_llm_config().get(key, default)).strip()


def invalidate_config_cache() -> None:
    """Call this after saving a new org_config.yaml so the next call re-reads it."""
    global _llm_config_cache
    _llm_config_cache = None


# ── Public helpers ─────────────────────────────────────────────────────────────

def get_provider() -> str:
    return _cfg("provider", "cursor").lower()


def get_model(hint: str | None = None) -> str:
    if hint:
        return hint
    configured = _cfg("model")
    if configured:
        return configured
    return _DEFAULT_MODELS.get(get_provider(), "unknown")


# ── Provider implementations ───────────────────────────────────────────────────

def _chat_cursor(prompt: str, history: list[dict]) -> str:
    base = _cfg("api_url") or os.getenv("CURSOR_PROXY_URL", "http://localhost:3000").rstrip("/")
    url = f"{base}/api/chat"
    payload: dict = {"message": prompt}
    if history:
        payload["history"] = history
    logging.debug(f"[llm/cursor] POST {url}  len={len(prompt)}")
    resp = requests.post(url, json=payload, timeout=_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    return data.get("reply") or data.get("content") or ""


def _chat_openai(prompt: str, history: list[dict]) -> str:
    base = (_cfg("api_url") or "https://api.openai.com/v1").rstrip("/")
    url = f"{base}/chat/completions"
    model = get_model()
    api_key = _cfg("api_key")
    if not api_key:
        raise ValueError("LLM provider is 'openai' but no api_key is configured.")

    messages = []
    for m in (history or []):
        messages.append({"role": m.get("role", "user"), "content": m.get("content", "")})
    messages.append({"role": "user", "content": prompt})

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {"model": model, "messages": messages, "temperature": 0.1}
    logging.debug(f"[llm/openai] POST {url}  model={model}  len={len(prompt)}")
    resp = requests.post(url, json=payload, headers=headers, timeout=_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    _record_openai_usage(data, model)
    return data["choices"][0]["message"]["content"]


def _chat_anthropic(prompt: str, history: list[dict]) -> str:
    base = (_cfg("api_url") or "https://api.anthropic.com").rstrip("/")
    url = f"{base}/v1/messages"
    model = get_model()
    api_key = _cfg("api_key")
    if not api_key:
        raise ValueError("LLM provider is 'anthropic' but no api_key is configured.")

    messages = []
    for m in (history or []):
        messages.append({"role": m.get("role", "user"), "content": m.get("content", "")})
    messages.append({"role": "user", "content": prompt})

    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    payload = {"model": model, "max_tokens": 1024, "messages": messages}
    logging.debug(f"[llm/anthropic] POST {url}  model={model}  len={len(prompt)}")
    resp = requests.post(url, json=payload, headers=headers, timeout=_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    _record_anthropic_usage(data, model)
    return data["content"][0]["text"]


def _chat_claude_cli(prompt: str, history: list[dict]) -> str:
    """Run the local `claude` CLI in-pod via your Claude subscription (no API cost).

    Authentication is the logged-in `claude` session (see Authenticate button /
    `claude auth login`), managed in dementor_sca.claude_session. No api_key needed.
    """
    from dementor_sca import claude_session

    full = prompt
    if history:
        convo = "\n".join(f"{m.get('role','user')}: {m.get('content','')}" for m in history)
        full = f"{convo}\nuser: {prompt}"
    logging.debug(f"[llm/claude_cli] subprocess `claude -p`  len={len(full)}")
    return claude_session.call(full, timeout=_TIMEOUT, model=get_model())


def _chat_gemini(prompt: str, history: list[dict]) -> str:
    """Google Gemini via its OpenAI-compatible endpoint."""
    base = (_cfg("api_url") or "https://generativelanguage.googleapis.com/v1beta/openai").rstrip("/")
    url = base if base.endswith("/completions") else f"{base}/chat/completions"
    model = get_model()
    api_key = _cfg("api_key")
    if not api_key:
        raise ValueError("LLM provider is 'gemini' but no api_key is configured (Google AI Studio key).")

    messages = []
    for m in (history or []):
        messages.append({"role": m.get("role", "user"), "content": m.get("content", "")})
    messages.append({"role": "user", "content": prompt})

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {"model": model, "messages": messages, "temperature": 0.1}
    logging.debug(f"[llm/gemini] POST {url}  model={model}  len={len(prompt)}")
    resp = requests.post(url, json=payload, headers=headers, timeout=_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    _record_openai_usage(data, model)
    return data["choices"][0]["message"]["content"]


def _chat_custom(prompt: str, history: list[dict]) -> str:
    """OpenAI-compatible endpoint (Ollama, LM Studio, vLLM, Together AI, etc.)"""
    base = _cfg("api_url")
    if not base:
        raise ValueError("LLM provider is 'custom' but no api_url is configured.")
    base = base.rstrip("/")
    # auto-append /chat/completions if only a base URL was given
    url = base if base.endswith("/completions") else f"{base}/chat/completions"
    model = get_model()
    api_key = _cfg("api_key")  # optional

    messages = []
    for m in (history or []):
        messages.append({"role": m.get("role", "user"), "content": m.get("content", "")})
    messages.append({"role": "user", "content": prompt})

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload = {"model": model, "messages": messages, "temperature": 0.1}
    logging.debug(f"[llm/custom] POST {url}  model={model}  len={len(prompt)}")
    resp = requests.post(url, json=payload, headers=headers, timeout=_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    # Handle both OpenAI-style and Ollama-style responses
    if "choices" in data:
        return data["choices"][0]["message"]["content"]
    return data.get("reply") or data.get("content") or data.get("message", {}).get("content", "")


# ── Main entry point ───────────────────────────────────────────────────────────

def _call_with_backoff(call):
    """Dynamic rate-limit handling: retry the LLM call with exponential backoff (honoring the
    provider's Retry-After header) on 429 / transient 5xx / quota errors. Lets parallel reachability
    workers ride out free-tier rate limits (e.g. Gemini) instead of failing the finding.

    Tunable via env: LLM_MAX_RETRIES (default 5), LLM_BACKOFF_BASE seconds (2), LLM_BACKOFF_MAX (60).
    Set LLM_MAX_RETRIES=0 to disable."""
    import time, random
    max_retries = int(os.getenv("LLM_MAX_RETRIES", "5"))
    backoff_max = float(os.getenv("LLM_BACKOFF_MAX", "60"))
    delay = float(os.getenv("LLM_BACKOFF_BASE", "2"))
    for attempt in range(max_retries + 1):
        try:
            return call()
        except Exception as e:
            resp = getattr(e, "response", None)
            code = getattr(resp, "status_code", None)
            msg = str(e).lower()
            retryable = (code in (429, 500, 502, 503, 504)
                         or (isinstance(e, requests.RequestException) and not isinstance(e, requests.HTTPError))
                         or any(k in msg for k in ("rate limit", "ratelimit", "quota",
                                                   "resource_exhausted", "too many requests")))
            if not retryable or attempt >= max_retries:
                raise
            # Prefer the server's Retry-After (seconds); else exponential backoff. Add jitter.
            ra = None
            try:
                hdr = resp.headers.get("Retry-After") if resp is not None else None
                ra = float(hdr) if hdr else None
            except (ValueError, AttributeError):
                ra = None
            wait = min(ra if ra is not None else delay, backoff_max) + random.uniform(0, 1.0)
            logging.warning(f"[llm_client] rate-limited/transient (status={code}); backing off "
                            f"{wait:.1f}s — retry {attempt + 1}/{max_retries}")
            time.sleep(wait)
            delay = min(delay * 2, backoff_max)


def chat(prompt: str, history: list[dict] | None = None) -> str:
    """
    Send a prompt to the configured LLM provider and return the reply text.

    Reads provider / api_url / api_key / model from (in priority order):
        1. Environment variables (LLM_PROVIDER, LLM_API_URL, LLM_API_KEY, LLM_MODEL)
        2. config/org_config.yaml  llm:  section
        3. Defaults (cursor proxy at localhost:3000)

    Rate-limited / transient failures are retried with adaptive backoff (see _call_with_backoff).
    """
    provider = get_provider()
    history = history or []

    _dispatch = {
        "cursor":     _chat_cursor,
        "openai":     _chat_openai,
        "anthropic":  _chat_anthropic,
        "claude_cli": _chat_claude_cli,
        "gemini":     _chat_gemini,
        "custom":     _chat_custom,
    }
    fn = _dispatch.get(provider)
    if fn is None:
        logging.warning(f"[llm_client] Unknown provider '{provider}' — falling back to cursor proxy")
        fn = _chat_cursor

    logging.info(f"[llm_client] provider={provider}  model={get_model()}")
    return _call_with_backoff(lambda: fn(prompt, history))


def health() -> dict:
    """
    Check LLM provider connectivity.
    For cursor: calls /api/health.
    For others: returns a static status dict (no cheap health endpoint).
    """
    provider = get_provider()
    if provider == "cursor":
        base = _cfg("api_url") or os.getenv("CURSOR_PROXY_URL", "http://localhost:3000").rstrip("/")
        try:
            resp = requests.get(f"{base}/api/health", timeout=10)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            return {"status": "error", "error": str(e)}
    return {"status": "ok", "provider": provider, "model": get_model()}
