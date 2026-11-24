#!/usr/bin/env python3
"""Check one existing Inkling probe candidate against Spore's VC9 fingerprint.

The probe uses a simplified free-function signature for __thiscall. VC9 needs
a real member function for the ECX ABI, and has no <cstdint>. This script builds
a minimal ABI-equivalent wrapper in Spore's ignored work/ directory, then asks
Spore's own VC9 compile and fingerprint modules for a verdict.

It never edits the original candidate, Spore's tracked sources, or manifests.
It does not call an LLM or run equivalence proofs.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

try:
    from .fixed_width_types import CPP_FIXED_WIDTH_TYPES
except ImportError:
    from fixed_width_types import CPP_FIXED_WIDTH_TYPES

ROOT = Path(__file__).resolve().parents[1]
VA = 0x00672CF0


def candidate_body(candidate_text: str) -> str:
    # Import only the constant: keep the test specific to this probe ABI.
    try:
        from scripts.probe_body import PREFIX
    except ModuleNotFoundError:
        from probe_body import PREFIX
    if not candidate_text.startswith(PREFIX) or not candidate_text.rstrip().endswith("}"):
        raise ValueError("Expected the unmodified 00672cf0 probe prefix and one function body")
    body = candidate_text[len(PREFIX):].rstrip()[:-1].strip()
    if not body:
        raise ValueError("Empty candidate body")
    # Callers pass their own object as ECX. A genuine member call has the same
    # ABI without relying on VC9 accepting __thiscall for a free function.
    pattern = re.compile(
        r"(?m)^([ \t]*)FUN_00672750\(\s*param_1\s*,\s*([^,\n]+?)\s*,\s*([^,\n]+?)\s*\);[ \t]*$"
    )
    body, count = pattern.subn(
        lambda m: f"{m.group(1)}this->FUN_00672750({m.group(2).strip()}, {m.group(3).strip()});",
        body,
    )
    if count != 1 or body.count("FUN_00672750(") != 1:
        raise ValueError("Expected exactly one direct callee call using param_1 as this")
    return body


def render_vc9_source(candidate_text: str) -> str:
    body = candidate_body(candidate_text)
    return (
        "// Generated test wrapper, never published in match/slices.\n"
        "// VC9 predates <cstdint>; the probe and VC9 share fixed-width aliases.\n"
        + CPP_FIXED_WIDTH_TYPES + "\n"
        "struct InklingCandidate_s00672cf0 {\n"
        "    int* __thiscall FUN_00672750(int* begin, int* end);\n"
        "    int* __thiscall FUN_00672cf0(int* param_2);\n"
        "};\n\n"
        "// @ 0x00672cf0\n"
        "int* InklingCandidate_s00672cf0::FUN_00672cf0(int* param_2) {\n"
        "    int* param_1 = (int*)this;\n"
        + body + "\n}\n"
    )


def verify_in_spore(repo: Path, source: Path) -> int:
    # Imports and the toolchain are loaded by the caller's own Spore venv.
    for dirname in ("tools/contrib", "tools/difftest", "tools/matching", "tools/ci"):
        sys.path.insert(0, str(repo / dirname))
    import task as T
    import slice as S
    import fingerprint as F
    from coff import Coff

    fp = T.fingerprint(VA)
    if not fp:
        print("ERROR: Spore fingerprint for 0x00672cf0 not found")
        return 2

    flags, provenance = S.choose_flags("s00672cf0", VA)
    print(f"VC9 flags: {' '.join(flags)} ({provenance})", flush=True)
    obj, log = S.compile_obj(str(source), flags)
    if not obj:
        print("VC9 COMPILE FAILED")
        print(log or "(no compiler diagnostics)")
        return 1

    coff = Coff(obj)
    symbol_names = [s for s in coff.functions() if s.startswith("?FUN_00672cf0@InklingCandidate_s00672cf0@@")]
    if len(symbol_names) != 1:
        print(f"ERROR: expected one generated method symbol, found {symbol_names}")
        return 2
    symbol = symbol_names[0]
    secs, syms = F.parse_coff(obj)
    data, relocations = F.extract(secs, syms, symbol)
    verdict = F.check(fp, data, relocations)
    print(f"VC9 COMPILE PASS | compiled {len(data)} bytes | retail {fp['size']} bytes")
    print(f"Fingerprint check: {verdict}")
    print(f"Object: {obj}")
    print(f"Symbol: {symbol}")
    if verdict == "PASS":
        print(
            "BYTE MATCH against the retail fingerprint (relocations masked). "
            "The test wrapper's external callee symbol is synthetic, so "
            "its link target is not independently verified."
        )
        return 0

    image = repo / "work" / "SporeApp.analysis.bin"
    if image.is_file():
        print("\nInstruction diff (retail | candidate):", flush=True)
        cmpdis = repo / "tools" / "matching" / "cmpdis.py"
        proc = subprocess.run(
            [sys.executable, str(cmpdis), obj, symbol, f"{VA:08x}"],
            cwd=repo, check=False,
        )
        if proc.returncode:
            print(f"Instruction diff exited {proc.returncode}")
    else:
        print("Retail analysis image missing, so no instruction-level diff is available.")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("candidate", nargs="?", type=Path,
                    default=ROOT / "cases/00672cf0/probe_prompt_v004_run001_repair001.cpp")
    ap.add_argument("--spore-repo", type=Path,
                    help="Spore repo path; defaults to config.json's spore.repo_path")
    ap.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--prepared-source", type=Path, help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.spore_repo:
        repo = args.spore_repo.expanduser().resolve()
    else:
        cfg = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
        repo = Path(cfg["spore"]["repo_path"]).expanduser().resolve()

    if args.worker:
        if not args.prepared_source:
            ap.error("Worker requires --prepared-source")
        return verify_in_spore(repo, args.prepared_source.resolve())

    if not (repo / "tools/contrib/check.py").is_file():
        ap.error(f"Not a spore-decomp checkout: {repo}")
    candidate = args.candidate.expanduser().resolve()
    if not candidate.is_file():
        ap.error(f"Candidate not found: {candidate}")
    try:
        source = render_vc9_source(candidate.read_text(encoding="utf-8"))
    except ValueError as exc:
        ap.error(str(exc))

    # Generated sources only in ignored work/. Nothing tracked is replaced.
    outdir = repo / "work" / "pcode2cpp_checks"
    outdir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:12]
    prepared = outdir / f"candidate_00672cf0_{digest}.cpp"
    prepared.write_text(source, encoding="utf-8")
    print(f"Original Inkling candidate (unchanged): {candidate}")
    print(f"VC9 wrapper: {prepared}")

    spore_python = repo / ".venv" / "bin" / "python"
    if not spore_python.is_file():
        ap.error(f"Spore Python environment not found: {spore_python}")
    command = [str(spore_python), str(Path(__file__).resolve()),
               "--worker", "--spore-repo", str(repo), "--prepared-source", str(prepared)]
    try:
        completed = subprocess.run(command, cwd=repo, check=False, timeout=600)
    except subprocess.TimeoutExpired:
        print("VC9 verification timed out after 600 seconds")
        return 2
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
