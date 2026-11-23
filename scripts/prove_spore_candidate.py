#!/usr/bin/env python3
"""Prove equivalence of an existing Inkling candidate against retail Spore.

Reuses the VC9 wrapper and compiles it into Spore's ignored work/ directory,
then invokes Spore's *existing* prove.run with that particular object as ours.
Never looks up a tracked Spore implementation as the candidate, writes proof
records, changes manifests, or contacts the model. Default: rename + angr.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from verify_spore_vc9 import ROOT, VA, render_vc9_source


def prepare_source(repo: Path, candidate: Path) -> Path:
    content = render_vc9_source(candidate.read_text(encoding="utf-8"))
    outdir = repo / "work" / "pcode2cpp_checks"
    outdir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
    output = outdir / f"candidate_00672cf0_{digest}.cpp"
    if output.exists():
        if output.read_text(encoding="utf-8") != content:
            raise ValueError(f"Existing generated wrapper differs: {output}")
    else:
        output.write_text(content, encoding="utf-8")
    return output


def verify_compiled_candidate(repo: Path, source: Path, layers: list[str], timeout: float, mutants: int) -> int:
    for dirname in ("tools/equiv", "tools/contrib", "tools/difftest", "tools/matching", "tools/ci"):
        sys.path.insert(0, str(repo / dirname))
    import func as FN
    import task as T
    import slice as S
    import prove as P
    from coff import Coff

    if not (repo / "work" / "SporeApp.analysis.bin").is_file():
        print("ERROR: Spore retail analysis image missing under work/SporeApp.analysis.bin.")
        return 2
    fp = T.fingerprint(VA)
    if not fp:
        print(f"ERROR: no Spore retail fingerprint for 0x{VA:08x}")
        return 2

    flags, provenance = S.choose_flags("s00672cf0", VA)
    print(f"VC9 flags: {' '.join(flags)} ({provenance})", flush=True)
    obj, compile_log = S.compile_obj(str(source), flags)
    if obj is None:
        print("VC9 COMPILE FAILED\n" + (compile_log or "(no diagnostics)"))
        return 1

    from verify_spore_vc9 import render_vc9_source as unused  # noqa: F401
    symbol_prefix = "?FUN_00672cf0@InklingCandidate_s00672cf0@@"
    names = [name for name in Coff(obj).functions() if name.startswith(symbol_prefix)]
    if len(names) != 1:
        print(f"ERROR: couldn't identify the compiled candidate symbol: {names}")
        return 2

    ours = FN.obj_func(obj, names[0])
    ours.meta.update({
        "src": str(source.relative_to(repo)),
        "flags": flags,
        "symbol": names[0],
        "ret64": False,
    })
    print(f"Candidate source: {source}")
    print(f"Candidate object: {obj}")
    print(f"Candidate symbol: {names[0]}")
    print(f"Retail: {fp['size']} bytes | Candidate: {len(ours.code)} bytes", flush=True)
    print("External callee: synthetic wrapper symbol, equivalence layer must validate address pairing.", flush=True)

    # Spore's public prove.run calls func.our_func(va) to load a tracked source.
    # Override only this in the current worker, so its existing retail model,
    # register facts, proof levels and mutant self-tests operate on OUR object.
    original = FN.our_func
    FN.our_func = lambda va, flags=None: ours if va == VA else original(va, flags)
    try:
        outcome = P.run(VA, layers, timeout, k_mutants=mutants)
    finally:
        FN.our_func = original

    verdict = outcome["verdict"]
    print(f"\n{verdict} 0x{VA:08x}  {outcome.get('layer', '')} {outcome.get('level', '')}")
    if outcome.get("detail"):
        print("Detail: " + str(outcome["detail"]))
    if verdict == "EQUIVALENT":
        print(f"Proof candidate hash: {outcome['bundle']['build']}")
        print("Proof in memory only. No equivalent.txt or proof bundle was recorded.")
    elif verdict == "UNKNOWN":
        print("No equivalence established. UNKNOWN is not proof of incorrectness.")
    elif verdict == "REFUTED":
        print("The prover identified an observable difference; inspect its detail.")
    return 0 if verdict in ("MATCH", "EQUIVALENT") else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", nargs="?", type=Path,
                        default=ROOT / "cases/00672cf0/probe_prompt_v004_run001_repair001.cpp")
    parser.add_argument("--spore-repo", type=Path,
                        help="Spore checkout; defaults to config.json spore.repo_path")
    parser.add_argument("--layers", default="rename,angr_layer",
                        help="Comma-separated existing proof layers (default: rename,angr_layer)")
    parser.add_argument("--timeout", type=float, default=300,
                        help="Seconds per proof layer, including each mutant (default: 300)")
    parser.add_argument("--mutants", type=int, default=5,
                        help="Mutants to reject before accepting a proof (default: 5)")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--prepared-source", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.timeout <= 0 or args.mutants < 1:
        parser.error("--timeout must be positive and --mutants at least 1")
    layers = [("angr_layer" if name == "angr" else name.strip()) for name in args.layers.split(",")]
    if not layers or any(layer not in ("rename", "angr_layer", "ddec_layer") for layer in layers):
        parser.error("--layers must only contain rename, angr, angr_layer, or ddec_layer")

    if args.spore_repo:
        repo = args.spore_repo.expanduser().resolve()
    else:
        config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
        repo = Path(config["spore"]["repo_path"]).expanduser().resolve()
    if not (repo / "tools/contrib/prove.py").is_file():
        parser.error(f"Not a Spore checkout: {repo}")

    if args.worker:
        if args.prepared_source is None:
            parser.error("--worker requires --prepared-source")
        src = args.prepared_source.resolve()
        try:
            src.relative_to((repo / "work" / "pcode2cpp_checks").resolve())
        except ValueError:
            parser.error("Worker may only test sources inside Spore's ignored work/pcode2cpp_checks")
        return verify_compiled_candidate(repo, src, layers, args.timeout, args.mutants)

    candidate = args.candidate.expanduser().resolve()
    if not candidate.is_file():
        parser.error(f"Candidate missing: {candidate}")
    try:
        prepared = prepare_source(repo, candidate)
    except ValueError as exc:
        parser.error(str(exc))

    python = repo / ".venv/bin/python"
    if not python.is_file():
        parser.error(f"Spore virtual environment missing: {python}")
    command = [
        str(python), str(Path(__file__).resolve()),
        "--spore-repo", str(repo), "--worker", "--prepared-source", str(prepared),
        "--layers", ",".join(layers), "--timeout", str(args.timeout),
        "--mutants", str(args.mutants)
    ]
    print(f"Original Inkling candidate (unchanged): {candidate}", flush=True)
    print(f"Testing exact candidate through VC9 wrapper: {prepared}", flush=True)
    # Do not set a single global timeout: individual solver steps have their
    # own limits, and mutant checks may legitimately repeat them.
    return subprocess.run(command, cwd=repo, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
