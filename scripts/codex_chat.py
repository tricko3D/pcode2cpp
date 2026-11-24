"""ChatGPT-authenticated Codex CLI transport for pcode2cpp's normal model_client.

The caller owns reconstruction, repairs, mechanical matching and AI fallback.
This module only turns a chat_json message list into one tool-free Codex response.
"""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile

try:
    from .model_client import ModelError
except ImportError:
    from model_client import ModelError


_BODY_SCHEMA = {
    "type": "object",
    "properties": {"body": {"type": "string"}},
    "required": ["body"],
    "additionalProperties": False,
}
_EDITS_SCHEMA = {
    "type": "object",
    "properties": {
        "edits": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "find": {"type": "string"},
                    "replace": {"type": "string"},
                    "hypothesis": {"type": "string"},
                },
                "required": ["find", "replace", "hypothesis"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["edits"],
    "additionalProperties": False,
}
_TOOL_ITEMS = {
    "command_execution", "mcp_tool_call", "file_change", "web_search",
    "plan_update", "collab_tool_call", "browser_tool_call",
}


def chat_codex(profile: dict, messages: list[dict]) -> tuple[dict, dict]:
    """Perform one Codex exec turn with schema-constrained JSON, rejecting tool use.

    Codex CLI is an agent harness, not a raw ChatGPT Plus API endpoint. Launch
    it in a fresh empty directory with a read-only sandbox and reject any
    reported tool activity. Source code is supplied only in the prompt.
    """
    binary = shutil.which("codex")
    if binary is None:
        raise ModelError("Codex CLI not found. Install @openai/codex and run codex login.")

    edits = messages[0].get("content", "").startswith(
        "You are proposing C++ source mutations"
    )
    schema = _EDITS_SCHEMA if edits else _BODY_SCHEMA
    role_messages = "\n\n".join(
        f"### {msg['role'].upper()} MESSAGE\n{msg['content']}"
        for msg in messages
    )
    prompt = (
        "This is an inference-only request from a C++ decompilation verifier. "
        "All evidence is in the following messages. Do not access the filesystem, "
        "execute commands, call tools, start subagents, search, or inspect repositories. "
        "Return ONLY a JSON object matching the required output schema; no prose "
        "or code fences.\n\n" + role_messages
    )

    with tempfile.TemporaryDirectory(prefix="pcode2cpp-codex-") as dirname:
        directory = Path(dirname)
        schema_path = directory / "schema.json"
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        command = [
            binary, "exec", "--sandbox", "read-only",
            "--skip-git-repo-check", "--ephemeral",
            "--json", "--output-schema", str(schema_path),
        ]
        if profile["model"] != "default":
            command.extend(["--model", profile["model"]])
        command.append("-")
        try:
            result = subprocess.run(
                command, input=prompt, text=True, capture_output=True,
                cwd=directory, timeout=profile.get("timeout_seconds", 1800),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ModelError(f"Codex CLI request failed: {exc}") from exc

    if result.returncode:
        raise ModelError(
            f"Codex CLI exited {result.returncode}: {result.stderr[-2000:]}"
        )

    answer = None
    usage = {}
    tool_items = []
    errors = []
    for line in result.stdout.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            continue
        event_type = event.get("type")
        item = event.get("item") or {}
        kind = item.get("type")
        if kind in _TOOL_ITEMS:
            tool_items.append(kind)
        if event_type in ("turn.failed", "error"):
            errors.append(event)
        if event_type == "item.completed" and kind == "agent_message":
            answer = item.get("text")
        if event_type == "turn.completed":
            usage = event.get("usage") or {}
    if errors:
        raise ModelError(f"Codex CLI reported errors: {errors[-1]}")
    if tool_items:
        raise ModelError(
            f"Codex used tools instead of inference-only output: {tool_items}"
        )
    if not isinstance(answer, str) or not answer.strip():
        raise ModelError(
            f"Codex returned no final message: {result.stderr[-1500:]}"
        )
    try:
        data = json.loads(answer.strip())
    except ValueError as exc:
        raise ModelError("Codex did not return JSON content") from exc
    if not isinstance(data, dict):
        raise ModelError("Codex output must be a JSON object")
    expected = "edits" if edits else "body"
    if expected not in data:
        raise ModelError(f"Codex output missing {expected!r}")
    return data, {
        "model": profile["model"], "profile": profile.get("name"),
        "provider": "codex_cli", "usage": usage, "finish_reason": "stop",
    }
