"""Tiny LLM client with no extra dependencies. Two adapters cover most providers:
  anthropic -> Anthropic Messages API
  openai    -> any OpenAI-compatible chat API (OpenAI, Groq, Ollama, Gemini's compatible endpoint...)
Settings come from environment variables or a .env file next to requirements.txt (see .env.example).

Features & Hardening
--------------------
- Multi-Key Support: Comma-separated API keys in .env (e.g. key1,key2,key3) with
  automatic fallback to the next key if one gets rate-limited (429) or fails.
- Cloudflare Protection: Includes desktop browser User-Agent header so providers
  behind Cloudflare (like Groq) don't block requests with HTTP 403 (error 1010).
- Automatic Retry: Exponential back-off on transient HTTP status codes.
- On-Disk Cache: TTL expiration and size-capped eviction to save costs and avoid disk bloat.
"""
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_ENV_LOADED = False


class LLMError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Lazy env load
# ---------------------------------------------------------------------------
def _load_env() -> None:
    global _ENV_LOADED
    if _ENV_LOADED:
        return
    _ENV_LOADED = True
    f = ROOT / ".env"
    if not f.is_file():
        return
    for line in f.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip("\"'"))


def config():
    """Returns the active provider settings, or None when no key is set.
    Supports single or multiple comma-separated API keys.
    """
    _load_env()
    prov = os.getenv("LLM_PROVIDER", "").lower()
    raw_anthropic = os.getenv("ANTHROPIC_API_KEY", "").strip()
    raw_openai = os.getenv("OPENAI_API_KEY", "").strip()

    if not prov:
        prov = "anthropic" if raw_anthropic else "openai" if raw_openai else ""

    if prov == "anthropic":
        keys = [k.strip() for k in raw_anthropic.split(",") if k.strip()]
        model = os.getenv("LLM_MODEL", "claude-haiku-5-5")
        base = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
    elif prov == "openai":
        keys = [k.strip() for k in raw_openai.split(",") if k.strip()]
        model = os.getenv("LLM_MODEL", "gpt-4o-mini")
        base = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    else:
        return None

    if not keys:
        return None

    return {
        "provider": prov,
        "key": keys[0],
        "keys": keys,
        "model": model,
        "base": base.rstrip("/"),
    }


# ---------------------------------------------------------------------------
# Retry with exponential back-off on transient errors
# ---------------------------------------------------------------------------
_RETRY_CODES = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3


def _post(url, headers, body, timeout=45):
    req_body = json.dumps(body).encode()
    all_headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CodeShieldAI/1.0",
        **headers,
    }
    last_err: Exception = RuntimeError("unknown error")
    for attempt in range(_MAX_RETRIES):
        req = urllib.request.Request(url, req_body, all_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            last_err = LLMError(f"HTTP {e.code}: {e.read()[:150].decode(errors='ignore')}")
            if e.code in _RETRY_CODES and attempt < _MAX_RETRIES - 1:
                time.sleep(2 ** attempt)   # 1 s, 2 s, 4 s
                continue
            raise last_err
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            last_err = LLMError(f"request failed: {e}")
            if attempt < _MAX_RETRIES - 1:
                time.sleep(2 ** attempt)
                continue
            raise last_err
    raise last_err


def _call(cfg, system, user, max_tokens=500, timeout=45):
    """Executes call with automatic multi-key fallback if configured."""
    keys = cfg.get("keys", [cfg["key"]])
    last_err = None

    for idx, key in enumerate(keys):
        try:
            if cfg["provider"] == "anthropic":
                r = _post(
                    cfg["base"] + "/v1/messages",
                    {"x-api-key": key, "anthropic-version": "2023-06-01"},
                    {
                        "model": cfg["model"],
                        "max_tokens": max_tokens,
                        "system": system,
                        "messages": [{"role": "user", "content": user}],
                    },
                    timeout,
                )
                return "".join(b.get("text", "") for b in r.get("content", []) if b.get("type") == "text")

            r = _post(
                cfg["base"] + "/chat/completions",
                {"Authorization": "Bearer " + key},
                {
                    "model": cfg["model"],
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
                timeout,
            )
            try:
                return r["choices"][0]["message"]["content"] or ""
            except (KeyError, IndexError, TypeError):
                raise LLMError("unexpected response shape")
        except LLMError as e:
            last_err = e
            # If multiple keys are available, failover to the next key
            if len(keys) > 1 and idx < len(keys) - 1:
                continue
            raise e

    if last_err:
        raise last_err


# ---------------------------------------------------------------------------
# Cache with TTL and max-entry cap
# ---------------------------------------------------------------------------
_CACHE_TTL  = int(os.getenv("LLM_CACHE_TTL",  str(86_400)))   # 24 h default
_CACHE_MAX  = int(os.getenv("LLM_CACHE_MAX",  "2000"))         # max entries


def _cache_path() -> Path:
    custom = os.getenv("LLM_CACHE", "")
    if custom:
        return Path(custom)
    base = Path(os.getenv("TMPDIR", os.getenv("TEMP", os.getenv("TMP", "/tmp"))))
    cache_dir = base / "csai_llm_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "cache.json"


def _load_cache(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_cache(path: Path, data: dict) -> None:
    now = time.time()
    data = {k: v for k, v in data.items() if now - v.get("ts", 0) < _CACHE_TTL}
    if len(data) > _CACHE_MAX:
        sorted_keys = sorted(data, key=lambda k: data[k].get("ts", 0))
        for k in sorted_keys[:len(data) - _CACHE_MAX]:
            del data[k]
    try:
        path.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass


def complete(cfg, system, user, max_tokens=500, timeout=45, cache=True):
    """Calls the model, with an on-disk cache so the same question is never paid for twice."""
    if not cache or os.getenv("LLM_CACHE", "").lower() == "disabled":
        return _call(cfg, system, user, max_tokens, timeout)
    path = _cache_path()
    key = hashlib.sha256(
        json.dumps([cfg["provider"], cfg["model"], system, user, max_tokens]).encode()
    ).hexdigest()
    cache_data = _load_cache(path)
    entry = cache_data.get(key)
    now = time.time()
    if entry and now - entry.get("ts", 0) < _CACHE_TTL:
        return entry["text"]
    text = _call(cfg, system, user, max_tokens, timeout)
    cache_data[key] = {"text": text, "ts": now}
    _save_cache(path, cache_data)
    return text
