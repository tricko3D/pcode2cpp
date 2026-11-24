#!/usr/bin/env python3
"""Select a large, genuinely unimplemented retail Spore function.

Uses Spore's own task.py logic for source/manifest/notes/library status.
Requires live claims information to avoid an active contributor's function.
Prints JSON so later experiments can record the exact target.
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys


SELECTOR = r'''
import json, os, sys
root = os.path.abspath(".")
sys.path[:0] = [root + "/tools/contrib", root + "/tools/matching",
                root + "/tools/difftest", root + "/tools/ci"]
import task as T

minimum, maximum = map(int, sys.argv[1:3])
candidates = T.never_tried(maximum)
marked = T.marked()
shapes = T.shape_only()
equivalent = T.equivalent()
claims = T.claims()
if claims is None:
    raise SystemExit("No live claims list; aborting instead of risking an active claim")
valid = [
    {"address": "0x%08x" % address, "retail_bytes": size}
    for size, address, *_ in candidates
    if minimum <= size <= maximum
    and address not in marked
    and address not in shapes
    and address not in equivalent
    and not os.path.exists(T.new_source_path(address))
    and not any(not T.stale(claim) for claim in claims.get(address, []))
]
valid.sort(key=lambda x: (-x["retail_bytes"], x["address"]))
print("BENCHMARK_SELECTION_JSON=" + json.dumps(valid[:20]))
'''


def select(spore: Path, minimum: int, maximum: int):
    command = [
        str(spore / ".venv/bin/python"), "-c", SELECTOR,
        str(minimum), str(maximum),
    ]
    run = subprocess.run(command, cwd=spore, text=True,
                         capture_output=True, timeout=360, check=False)
    if run.returncode:
        raise RuntimeError((run.stdout + run.stderr)[-4000:])
    prefix = "BENCHMARK_SELECTION_JSON="
    line = next((l for l in run.stdout.splitlines() if l.startswith(prefix)), None)
    if not line:
        raise RuntimeError("No selection produced: " + run.stdout[-1000:])
    return json.loads(line[len(prefix):])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--spore", type=Path, default=Path.home() / "spore-decomp")
    p.add_argument("--min-bytes", type=int, default=768)
    p.add_argument("--max-bytes", type=int, default=1536)
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--json", type=Path, help="Optionally save candidates for the benchmark record")
    a = p.parse_args()
    if not 0 < a.min_bytes <= a.max_bytes or a.top < 1:
        p.error("Invalid size range or --top")
    try:
        found = select(a.spore.expanduser().resolve(), a.min_bytes, a.max_bytes)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as e:
        print(f"select_large_spore: {e}", file=sys.stderr)
        return 2
    if not found:
        print("No eligible function in range", file=sys.stderr)
        return 1
    found = found[:a.top]
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(found, indent=2) + "\n")
    print(json.dumps(found, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
