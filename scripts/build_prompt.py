#!/usr/bin/env python3
"""Build a compact, readable reconstruction prompt from an existing Ghidra JSON export.

This script does not launch Ghidra, make LLM requests, or modify the input JSON.
"""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pcode2cpp.context import load_context  # noqa: E402

FENCE = chr(96) * 3
MAX_LAYOUTS = 48
MAX_FIELDS = 32
MAX_ENUM_VALUES = 32


def code_block(language, contents):
    return f"{FENCE}{language}\n{contents.rstrip()}\n{FENCE}"


def type_name(dtype):
    if isinstance(dtype, dict):
        return dtype.get("name") or dtype.get("path") or "unknown"
    return str(dtype) if dtype is not None else "unknown"


def varnode(node):
    if node is None:
        return "-"
    if not isinstance(node, dict):
        return str(node)
    storage = node.get("storage") or node.get("address") or "?"
    name = node.get("high_name")
    if name and name not in storage:
        return f"{storage}<{name}>"
    return str(storage)


def format_pcode(context):
    lines = []
    for block in context.get("basic_blocks", []):
        index = block.get("index", "?")
        targets = ", ".join(f"B{target}" for target in block.get("successors", [])) or "exit"
        lines.append(
            f"B{index}: {block.get('start', '?')}..{block.get('end', '?')} -> {targets}"
        )
    if lines:
        lines.append("")
    last_block = object()
    for op in context["high_pcode"]:
        block = op.get("block_index")
        if block != last_block:
            lines.append(f"; B{block}" if block is not None else "; unknown block")
            last_block = block
        args = ", ".join(varnode(node) for node in op.get("inputs", []))
        output = op.get("output")
        expression = f"{op.get('operation', '?')}({args})"
        if output is not None:
            expression = f"{varnode(output)} = {expression}"
        lines.append(f"{op.get('address', '?')}:{op.get('order', 0)} {expression}")
    return "\n".join(lines)


def format_assembly(context):
    return "\n".join(
        f"{instruction.get('address', '?')}: {instruction.get('instruction', '')}"
        for instruction in context["assembly"]
    )


def format_variables(function):
    lines = []
    for role, values in (
        ("param", function.get("parameters", [])),
        ("local", function.get("locals", [])),
    ):
        for value in values:
            name = value.get("name") or "unnamed"
            storage = value.get("storage") or "unknown storage"
            lines.append(f"- {role} {type_name(value.get('type'))} {name} [{storage}]")
    return "\n".join(lines)


def format_calls(context):
    lines = []
    for call in context["calls"]:
        site = call.get("site", "?")
        target = call.get("target")
        callee = call.get("callee") or {}
        signature = callee.get("signature") or callee.get("name") or "unknown signature"
        if target is None:
            lines.append(f"- {site} -> unresolved/indirect, {call.get('instruction', 'call')}")
        else:
            lines.append(f"- {site} -> {target}, {signature}")
    return "\n".join(lines)


def format_globals(context):
    lines = []
    for item in context["globals"]:
        access = "/".join(
            word for word, present in (
                ("read", item.get("read")), ("write", item.get("write"))
            ) if present
        ) or "referenced"
        name = item.get("symbol") or "unnamed"
        lines.append(
            f"- {item.get('address', '?')} {name}: "
            f"{type_name(item.get('data_type'))} ({access})"
        )
    return "\n".join(lines)


def format_types(context):
    # Primitive, pointer and empty placeholder entries are already represented
    # in signatures or decompiled C. Keep actual layouts and enum definitions.
    useful = [
        item for item in context["types"]
        if item.get("fields") or item.get("values") or item.get("underlying")
    ]
    lines = []
    for item in useful[:MAX_LAYOUTS]:
        name = item.get("path") or item.get("name") or "unknown type"
        lines.append(f"{name} ({item.get('kind', 'type')}, {item.get('size', '?')} bytes)")
        fields = item.get("fields", [])
        for field in fields[:MAX_FIELDS]:
            lines.append(
                f"  +{field.get('offset', '?')}: {type_name(field.get('type'))} "
                f"{field.get('name') or '<unnamed>'}"
            )
        if len(fields) > MAX_FIELDS:
            lines.append(f"  ... {len(fields) - MAX_FIELDS} more fields in original JSON")
        values = item.get("values", [])
        for value in values[:MAX_ENUM_VALUES]:
            lines.append(f"  {value.get('name', '?')} = {value.get('value', '?')}")
        if len(values) > MAX_ENUM_VALUES:
            lines.append(f"  ... {len(values) - MAX_ENUM_VALUES} more enum values in original JSON")
        if item.get("underlying"):
            lines.append(f"  alias of {type_name(item['underlying'])}")
    if len(useful) > MAX_LAYOUTS:
        lines.append(f"... {len(useful) - MAX_LAYOUTS} further definitions in original JSON")
    return "\n".join(lines)


def render_prompt(context, system_prompt):
    function = context["function"]
    program = context.get("program", {})
    header = [
        f"Program: {program.get('name', '?')}",
        f"Architecture: {program.get('language', '?')}",
        f"Compiler specification: {program.get('compiler_spec', '?')}",
        f"Function: {function.get('name', '?')}",
        f"Address: {function['address']}..{function.get('end', '?')}",
        f"Signature: {function.get('signature', '?')}",
        f"Calling convention: {function.get('calling_convention', '?')}",
    ]
    sections = [
        "# C++ reconstruction prompt",
        "## System instruction",
        system_prompt.strip(),
        "## Function identity",
        "\n".join(header),
        "## Decompiled C (Ghidra's best approximation)",
        code_block("c", context["pseudocode"]),
        "## Original assembly (instruction addresses retained)",
        code_block("asm", format_assembly(context)),
        "## High P-code (SSA operations and basic-block flow)",
        code_block("text", format_pcode(context)),
    ]

    details = (
        ("Known parameters and locals", format_variables(function)),
        ("Calls and targets", format_calls(context)),
        ("Referenced globals", format_globals(context)),
        ("Relevant type layouts and enums", format_types(context)),
    )
    for heading, content in details:
        if content:
            sections.extend((f"## {heading}", content))

    return "\n\n".join(sections) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Create a versioned Markdown prompt, without running inference."
    )
    parser.add_argument("context", type=Path, help="Ghidra context.json or bulk-exported JSON")
    parser.add_argument(
        "--system-prompt",
        type=Path,
        default=ROOT / "prompts" / "reconstruct.txt",
        help="System instruction text (default: prompts/reconstruct.txt)",
    )
    parser.add_argument(
        "--output-dir", type=Path,
        help="Destination (default: cases/<function-address>/)",
    )
    args = parser.parse_args()
    context = load_context(args.context.expanduser())
    instruction = args.system_prompt.expanduser().read_text(encoding="utf-8")
    if not instruction.strip():
        parser.error("System prompt is empty")

    address = int(context["function"]["address"], 16)
    destination = (
        args.output_dir.expanduser()
        if args.output_dir is not None else ROOT / "cases" / f"{address:08x}"
    )
    destination.mkdir(parents=True, exist_ok=True)
    content = render_prompt(context, instruction)

    # Exclusive creation ensures prompts from previous runs cannot be overwritten.
    version = 1
    while True:
        path = destination / f"prompt_v{version:03d}.md"
        try:
            with path.open("x", encoding="utf-8") as output:
                output.write(content)
            break
        except FileExistsError:
            version += 1

    print(f"Created {path}")
    print(f"Prompt characters: {len(content):,}")


if __name__ == "__main__":
    main()
