#!/usr/bin/env python3
"""One-shot Codex/ChatGPT reconstruction of Spore 0x00672CF0.

Uses the existing pcode2cpp initial reconstruction prompt and VC9 snapshot,
but does not run agents, repairs, C2Scope searches, or mutation sweeps.
Codex CLI is invoked non-interactively; any tool-use event invalidates the run.
"""

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pcode2cpp.context import load_context
from scripts import auto_match, build_prompt, check_candidate, run_pipeline

CASE = ROOT / "cases" / "00672cf0"
OUT = CASE / "codex_plus_once"
SPORE = Path.home() / "spore-decomp"
SCHEMA = {
    "type": "object",
    "properties": {"body": {"type": "string"}},
    "required": ["body"],
    "additionalProperties": False,
}
TOOL_TYPES = {
    "command_execution",
    "mcp_tool_call",
    "file_change",
    "web_search",
    "plan_update",
    "collab_tool_call",
    "browser_tool_call",
}


def main() -> int:
    codex = shutil.which("codex")
    if not codex:
        raise SystemExit("Codex CLI not found: npm install -g @openai/codex")
    source = CASE / "context.json"
    if not source.is_file():
        source = ROOT / "data" / "retail-contexts" / "00672cf0.json"
    if not source.is_file():
        raise SystemExit("Missing existing Ghidra context for 0x00672CF0")

    context = load_context(source)
    if int(context["function"]["address"], 16) != 0x00672CF0:
        raise SystemExit("Ghidra context is for the wrong function")
    callees, missing = build_prompt.read_direct_callees(
        context, ROOT / "data" / "retail-contexts"
    )
    messages = run_pipeline.initial_messages(context, callees, missing)

    # Keep the same fixed-prefix completion contract as the Inkling test.
    # The model is NOT given Spore-decomp's existing matching implementation.
    prompt = (
        "Single inference-only C++ reconstruction request. All input evidence is "
        "below. Do not use any tools, shell commands, files, searches, or agents. "
        "Do not seek the existing Spore-decomp solution. Output exactly one JSON "
        'object with a single key "body" containing the C++ function statements, '
        "with no enclosing function, Markdown or commentary.\n\n"
        + messages[0]["content"]
        + "\n\n"
        + messages[1]["content"]
    )

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "prompt.txt").write_text(prompt, encoding="utf-8")
    (OUT / "request.json").write_text(
        json.dumps({"function": "0x00672cf0", "context": str(source),
                    "callees": len(callees), "missing_callees": missing,
                    "messages": messages}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"Context: {source}", flush=True)
    print(f"Direct callees included: {len(callees)}", flush=True)
    print("Codex CLI: one read-only invocation, no tools requested", flush=True)
    with tempfile.TemporaryDirectory(prefix="pcode2cpp-codex-") as td:
        schema = Path(td) / "body.schema.json"
        schema.write_text(json.dumps(SCHEMA), encoding="utf-8")
        try:
            result = subprocess.run(
                [codex, "exec", "--sandbox", "read-only",
                 "--skip-git-repo-check", "--ephemeral", "--json",
                 "--output-schema", str(schema), "-"],
                input=prompt, text=True, capture_output=True, cwd=td,
                timeout=1800, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SystemExit("Codex request timed out after 30 minutes") from exc

    (OUT / "codex.jsonl").write_text(result.stdout, encoding="utf-8")
    (OUT / "codex.stderr.log").write_text(result.stderr, encoding="utf-8")
    if result.returncode:
        raise SystemExit(
            f"Codex exited {result.returncode}; see {OUT / 'codex.stderr.log'}"
        )

    answers = []
    tool_events = []
    failures = []
    for line in result.stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        kind = event.get("type")
        item = event.get("item") or {}
        item_type = item.get("type")
        if item_type in TOOL_TYPES:
            tool_events.append(item_type)
        if kind in ("turn.failed", "error"):
            failures.append(event)
        if kind == "item.completed" and item_type == "agent_message":
            answers.append(item.get("text", ""))

    if failures:
        raise SystemExit(f"Codex reported errors; see {OUT / 'codex.jsonl'}")
    if tool_events:
        raise SystemExit(
            f"Tool-free criterion failed, Codex used: {tool_events}. "
            f"See {OUT / 'codex.jsonl'}"
        )
    raw = answers[-1].strip() if answers else ""
    (OUT / "answer.txt").write_text(raw, encoding="utf-8")
    fence = chr(96) * 3
    if raw.startswith(fence):
        raw = re.sub(r"^" + fence + r"(?:json)?\s*\n?", "", raw, flags=re.I)
        raw = re.sub(r"\n?" + fence + r"\s*$", "", raw).strip()
    try:
        response = json.loads(raw)
    except ValueError as exc:
        raise SystemExit(
            f"Codex didn't return valid JSON; see {OUT / 'answer.txt'}"
        ) from exc

    candidate = OUT / "candidate.cpp"
    run_pipeline.write_candidate(candidate, response)
    print(f"Generated: {candidate}", flush=True)

    syntax = check_candidate.check_candidate(candidate)
    print(f"32-bit C++ syntax: {syntax.status}", flush=True)
    if not syntax.passed:
        print(f"Compiler diagnostics: {syntax.diagnostics_path}", flush=True)
        return 1

    if not SPORE.joinpath(".venv/bin/python").is_file():
        print("Spore toolchain unavailable; source and syntax result saved")
        return 1

    # Exactly one VC9 compilation through the existing pcode2cpp verifier.
    # This is the fingerprint comparison, not Spore's manifest checker.
    prepared = OUT / "prepared_vc9.cpp"
    prepared.write_text(
        auto_match.normalize_seed(SPORE, candidate), encoding="utf-8"
    )
    tag = "codex_" + hashlib.sha256(prepared.read_bytes()).hexdigest()[:12]
    try:
        state = auto_match.snapshot_prepared(SPORE, prepared, OUT, tag)
    except Exception as exc:
        print(f"VC9 snapshot failed: {exc}", flush=True)
        return 1

    (OUT / "verdict.json").write_text(
        json.dumps(state, indent=2), encoding="utf-8"
    )
    print(f"VC9 fingerprint: {state.get('fingerprint')}", flush=True)
    print(f"Candidate bytes: {state.get('candidate_bytes')}", flush=True)
    print(f"Callee symbol valid: {state.get('callee_symbol_valid')}", flush=True)
    print(f"Full VC9 results: {OUT / 'verdict.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
