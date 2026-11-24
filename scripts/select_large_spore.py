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
import datetime
import glob
import json
import os
import sys
import time
import urllib.request

root = os.path.abspath(".")
sys.path[:0] = [root + "/tools/contrib", root + "/tools/matching",
                root + "/tools/difftest", root + "/tools/ci"]
import task as T

minimum, maximum = map(int, sys.argv[1:3])
started = time.monotonic()

def stage(label):
    print(f"[selection +{time.monotonic()-started:.1f}s] {label}",
          file=sys.stderr, flush=True)

def read_shapes():
    # Older spore-decomp task.py versions lack shape_only().
    result = set()
    path = os.path.join(root, "match/shape_only.txt")
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as lines:
            for line in lines:
                parts = line.split("#", 1)[0].split()
                if parts:
                    try:
                        result.add(int(parts[0], 16))
                    except ValueError:
                        continue
    return result

def read_equivalent():
    # Older task.py versions may lack equivalent().
    result = set()
    for pattern in ("match/slices/*/equivalent.txt",
                    "src/game/**/equivalent.txt"):
        for filename in glob.glob(os.path.join(root, pattern), recursive=True):
            with open(filename, encoding="utf-8", errors="replace") as lines:
                for line in lines:
                    parts = line.split("#", 1)[0].split()
                    if len(parts) >= 3:
                        try:
                            result.add(int(parts[2], 16))
                        except ValueError:
                            continue
    return result

def read_claims():
    # No dependency on task.py's changing claims() implementation.
    # Use a fresh-enough local claims cache when present; otherwise fetch
    # the upstream claims index once, with a short timeout.
    cache = os.path.join(root, "work/claims.txt")
    url = "https://raw.githubusercontent.com/NoahBPeterson/spore-decomp/claims/claims.txt"
    raw = None
    if os.path.isfile(cache) and time.time() - os.path.getmtime(cache) < 600:
        with open(cache, encoding="utf-8") as f:
            raw = f.read()
    if raw is None:
        try:
            with urllib.request.urlopen(url, timeout=8) as response:
                raw = response.read().decode("utf-8", "replace")
            os.makedirs(os.path.dirname(cache), exist_ok=True)
            with open(cache, "w", encoding="utf-8") as f:
                f.write(raw)
        except Exception:
            if os.path.isfile(cache):
                with open(cache, encoding="utf-8") as f:
                    raw = f.read()
    if raw is None:
        raise RuntimeError("Cannot check upstream claims, and there is no local cache")
    active = set()
    cutoff = datetime.datetime.now(datetime.timezone.utc).date() - datetime.timedelta(days=7)
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 4 or not parts[0].lower().startswith("0x") or not parts[1].startswith("#"):
            continue
        try:
            va = int(parts[0], 16)
            modified = datetime.date.fromisoformat(parts[3][:10])
        except ValueError:
            # Unknown timestamp: treat the claim as active, not safe to take.
            active.add(va)
            continue
        if modified >= cutoff:
            active.add(va)
    return active

stage("Reading retail fingerprints, manifests and unstarted work")
candidates = T.never_tried(maximum)
stage(f"Candidate inventory loaded ({len(candidates)} functions)")
marked = T.marked()
stage("Checked existing source definitions")
shapes = read_shapes()
equivalent = read_equivalent()
stage("Checked matching-shape and equivalent records")
claims = read_claims()
stage("Checked active claims")

valid = [
    {"address": "0x%08x" % address, "retail_bytes": size}
    for size, address, *_ in candidates
    if minimum <= size <= maximum
    and address not in marked
    and address not in shapes
    and address not in equivalent
    and not os.path.isfile(
        "match/slices/s%08x/s%08x.cpp" % (address, address))
    and address not in claims
]
valid.sort(key=lambda x: (-x["retail_bytes"], x["address"]))
stage(f"Selected {len(valid)} eligible functions")
print("BENCHMARK_SELECTION_JSON=" + json.dumps(valid[:20]))
'''


def select(spore: Path, minimum: int, maximum: int):
    command = [
        str(spore / ".venv/bin/python"), "-c", SELECTOR,
        str(minimum), str(maximum),
    ]
    print("Selecting a large, not-yet-decompiled function from Spore...", file=sys.stderr, flush=True)
    # Show selector progress immediately; only capture the final machine-readable JSON.
    run = subprocess.run(command, cwd=spore, text=True,
                         stdout=subprocess.PIPE, timeout=240, check=False)
    if run.returncode:
        raise RuntimeError(run.stdout[-4000:] + f" (selector exit {run.returncode})")
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
