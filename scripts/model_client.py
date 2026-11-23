"""Small OpenAI-compatible chat client with explicit opt-in for remote APIs.

This module is independent of the original local-only pcode2cpp.translate API:
remote model support applies only to the opt-in CLI pipeline.
"""

import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class ModelError(RuntimeError):
    pass


def load_profile(path: Path, name: str, *, allow_remote: bool = False) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
        raise ValueError("Model profile name must contain only letters, digits, _ or -")
    config = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    profiles = config.get("profiles", {})
    if name not in profiles:
        raise ValueError(f"Model profile {name!r} not found in {path}")
    profile = dict(profiles[name])
    url = profile.get("url", "")
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or not parsed.path:
        raise ValueError("Model profile must supply a valid HTTP(S) chat-completions URL")
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("Never embed credentials or query parameters in the model endpoint")
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if not local and (not allow_remote or parsed.scheme != "https"):
        raise ValueError(
            "Remote inference requires --allow-remote and HTTPS. "
            "This sends code/assembly (and for initial inference, Ghidra data) to that provider."
        )
    if not profile.get("model"):
        raise ValueError("Model profile must specify a model identifier")
    env = profile.get("api_key_env")
    if env and not re.fullmatch(r"[A-Z_][A-Z_0-9]*", env):
        raise ValueError("api_key_env must be an environment-variable name, not a secret")
    if not local and not env:
        raise ValueError("Remote profile requires api_key_env")
    profile["name"] = name
    return profile


def chat_json(profile: dict, messages: list[dict], *, temperature: float | None = None,
              max_tokens: int | None = None, call=None) -> tuple[dict, dict]:
    """Return JSON object from completed assistant content; never parse reasoning.

    Accepts models that return JSON in plain text or a fenced code block.
    Request is deliberately tool-free and uses only standard chat completions.
    """
    if not messages:
        raise ValueError("At least one message is required")
    key_env = profile.get("api_key_env")
    api_key = os.environ.get(key_env) if key_env else None
    if key_env and not api_key:
        raise ModelError(f"Model credential environment variable {key_env} is unset")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    payload = {
        "model": profile["model"], "messages": messages,
        "temperature": profile.get("temperature", 0.2) if temperature is None else temperature,
        "max_tokens": profile.get("max_tokens", 8192) if max_tokens is None else max_tokens,
        "stream": False,
    }
    # Model-specific request additions, e.g. llama.cpp's Inkling thinking
    # controls. Never accept tools, arbitrary endpoint overrides or secrets.
    extras = profile.get("extra_body", {})
    if not isinstance(extras, dict) or any(k in payload or k in ("tools", "tool_choice", "api_key") for k in extras):
        raise ValueError("Unsupported extra_body keys")
    payload.update(extras)
    req = Request(profile["url"], data=json.dumps(payload).encode("utf-8"), headers=headers)
    sender = call or urlopen
    try:
        with sender(req, timeout=profile.get("timeout_seconds", 1800)) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise ModelError(f"Model request failed: {type(exc).__name__}: {exc}") from exc
    choices = data.get("choices") or []
    if not choices:
        raise ModelError("Model returned no chat completions")
    choice = choices[0]
    finish = choice.get("finish_reason")
    if finish not in (None, "stop"):
        raise ModelError(f"Incomplete model response: finish_reason={finish!r}")
    message = choice.get("message") or {}
    if message.get("tool_calls"):
        raise ModelError("Model tried to use tools, which are disabled")
    content = message.get("content")
    if isinstance(content, list):
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    if not isinstance(content, str) or not content.strip():
        raise ModelError("Model returned no final content")
    raw = content.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*\n?", "", raw, count=1, flags=re.I)
        raw = re.sub(r"\n?```\s*$", "", raw).strip()
    try:
        obj = json.loads(raw)
    except ValueError as exc:
        raise ModelError("Model did not produce valid JSON in its final answer") from exc
    if not isinstance(obj, dict):
        raise ModelError("Model response must be a JSON object")
    meta = {"model": profile["model"], "profile": profile.get("name"),
            "usage": data.get("usage", {}), "finish_reason": finish}
    return obj, meta
