"""Validate Ghidra's complete, per-function JSON export and construct model input."""

import json
from pathlib import Path
from typing import Any


REQUIRED_LISTS = ("high_pcode", "basic_blocks", "assembly", "calls", "globals", "types", "variables")


def validate_context(ctx: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(ctx, dict):
        raise ValueError("Ghidra export must be a JSON object")
    if ctx.get("schema_version") != 1:
        raise ValueError("Unsupported or missing schema_version (expected 1)")
    fn = ctx.get("function")
    if not isinstance(fn, dict) or not isinstance(fn.get("address"), str) or not fn.get("name"):
        raise ValueError("Missing function address/name")
    try:
        int(fn["address"], 16)
    except ValueError as exc:
        raise ValueError("Function address must be hexadecimal") from exc
    if not isinstance(ctx.get("pseudocode"), str) or not ctx["pseudocode"].strip():
        raise ValueError("Missing decompiled C pseudocode")
    for name in REQUIRED_LISTS:
        if not isinstance(ctx.get(name), list):
            raise ValueError(f"Missing or invalid {name} list")
    if not ctx["high_pcode"]:
        raise ValueError("High P-code is empty; exporter/decompilation probably failed")
    if not ctx["assembly"]:
        raise ValueError("Assembly listing is empty")
    for call in ctx["calls"]:
        if not isinstance(call, dict) or not call.get("site") or "target" not in call:
            raise ValueError("Every call requires site and target (null for unresolved)")
    return ctx


def load_context(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as fh:
        return validate_context(json.load(fh))


def context_json(ctx: dict[str, Any]) -> str:
    """Serialize EVERY extracted field, without filtering or truncating context."""
    return json.dumps(validate_context(ctx), indent=2, sort_keys=True, ensure_ascii=False)
