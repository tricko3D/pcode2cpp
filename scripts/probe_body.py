#!/usr/bin/env python3
"""Stream a constrained C++-body probe using a versioned Markdown prompt.

Runs against the configured local llama.cpp endpoint. Does not change model,
server settings, config.json, the prompt, or Ghidra exports.
"""
import json
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "cases" / "00672cf0"

PREFIX = (
    "#include <cstdint>\n\n"
    "int* __thiscall FUN_00672750(int* self, int* begin, int* end);\n\n"
    "int* __thiscall FUN_00672cf0(int* param_1, int* param_2) {\n"
)

SCHEMA = {
    "type": "object",
    "properties": {"body": {"type": "string"}},
    "required": ["body"],
    "additionalProperties": False,
}


def main():
    prompts = [
        p for p in CASE.iterdir()
        if re.fullmatch(r"prompt_v\d+\.md", p.name)
    ]
    if not prompts:
        raise SystemExit("No versioned prompt; run scripts/build_prompt.py first")
    prompt = max(prompts, key=lambda p: int(re.search(r"v(\d+)", p.stem).group(1)))
    document = prompt.read_text(encoding="utf-8")
    if "\n## Inkling response\n" in document:
        raise SystemExit(
            f"{prompt.name} contains a previous run; generate a fresh prompt"
        )

    marker = "## System instruction\n\n"
    separator = "\n\n## Function identity\n\n"
    system, evidence = document.split(marker, 1)[1].split(separator, 1)
    system = system.split("\nOUTPUT\n", 1)[0].rstrip() + (
        "\n\nOUTPUT\nFor this diagnostic test, return a valid JSON object "
        "with exactly one string key, 'body'. Its value must be only the "
        "C++ statements inside the provided function, without a function "
        "signature, header, enclosing braces, or commentary. No reasoning "
        "or explanations in 'body'."
    )
    fence = chr(96) * 3
    user = (
        "## Function identity\n\n" + evidence
        + "\n\n## C++ completion experiment\n"
        "Complete only the statements in the function below. The prefix is "
        "fixed and will be inserted automatically. Do not reproduce or "
        "modify it. Do not add declarations or debate linkage. "
        "Return JSON containing only the missing body.\n\n"
        + fence + "cpp\n" + PREFIX + "    // YOUR BODY GOES HERE\n}\n"
        + fence + "\n"
    )

    cfg = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))["llm"]
    payload = {
        "model": cfg.get("model", "local"),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": cfg.get("temperature", 0),
        "max_tokens": cfg.get("max_tokens", 32768),
        "stream": True,
        "response_format": {"type": "json_schema", "schema": SCHEMA},
    }

    stem = f"probe_{prompt.stem}"
    number = 1
    while (CASE / f"{stem}_run{number:03d}.log").exists():
        number += 1
    base = CASE / f"{stem}_run{number:03d}"
    log_path = Path(str(base) + ".log")
    answer = []
    finish_reason = None
    state = None
    print(f"Input prompt: {prompt}", flush=True)
    print(f"Output tokens: {payload['max_tokens']} (from config.json)", flush=True)
    print("Streaming reasoning and schema-constrained JSON:\n", flush=True)

    req = Request(
        cfg.get("url", "http://127.0.0.1:8080/v1/chat/completions"),
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlopen(req, timeout=cfg.get("timeout_seconds", 1800)) as response:
            with log_path.open("x", encoding="utf-8") as log:
                for raw in response:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    event = json.loads(data)
                    if "error" in event:
                        raise RuntimeError(str(event["error"]))
                    for choice in event.get("choices", ()):
                        delta = choice.get("delta") or {}
                        for section, part in (
                            ("Reasoning", delta.get("reasoning_content") or delta.get("reasoning") or ""),
                            ("JSON", delta.get("content") or ""),
                        ):
                            if not part:
                                continue
                            if state != section:
                                state = section
                                print(f"\n[{section}]\n", flush=True)
                                log.write(f"\n[{section}]\n")
                            print(part, end="", flush=True)
                            log.write(part)
                            log.flush()
                            if section == "JSON":
                                answer.append(part)
                        finish_reason = choice.get("finish_reason") or finish_reason
    except HTTPError as exc:
        raise SystemExit(
            f"llama.cpp rejected the request ({exc.code}): "
            + exc.read().decode("utf-8", errors="replace")
        ) from exc

    print(f"\n\nFinish reason: {finish_reason}; transcript: {log_path}", flush=True)
    if not answer:
        raise SystemExit("Inkling produced no final JSON; reasoning transcript saved")
    try:
        body = json.loads("".join(answer))["body"]
    except (ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"No valid C++ body in returned JSON: {exc}") from exc
    code_path = Path(str(base) + ".cpp")
    code_path.write_text(PREFIX + body.strip("\n") + "\n}\n", encoding="utf-8")
    print(f"Candidate: {code_path}", flush=True)

    # A single local syntax/type check. Diagnostics are written to disk;
    # there is deliberately no repair prompt or additional model request.
    from check_candidate import check_candidate

    result = check_candidate(code_path)
    print(
        f"Compiler check: {result.status}; diagnostics: {result.diagnostics_path}",
        flush=True,
    )
    if not result.passed:
        print(result.diagnostics, flush=True)


if __name__ == "__main__":
    main()
