#!/usr/bin/env python3
"""Opt-in C2Scope -> Inkling byte-matching experiment for Spore 0x00672cf0.

Only uses the candidate's VC9 wrapper in ignored work/ and local cases/ files.
It never reads the tracked upstream implementation as the candidate, edits
manifests, or retransmits the original Ghidra/High P-code context to Inkling.
"""

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from .probe_body import PREFIX, ROOT, SCHEMA
    from .check_candidate import check_candidate
    from .verify_spore_vc9 import VA
    from .prove_spore_candidate import prepare_source
    from .repair_candidate import extract_body
except ImportError:
    from probe_body import PREFIX, ROOT, SCHEMA
    from check_candidate import check_candidate
    from verify_spore_vc9 import VA
    from prove_spore_candidate import prepare_source
    from repair_candidate import extract_body

FUNC = "?FUN_00672cf0@InklingCandidate_s00672cf0@@QAEPAHPAH@Z"
FLAGS = ("/O2", "/MD", "/Gy", "/EHsc", "/TP")
DEFAULT_CANDIDATE = ROOT / "cases/00672cf0/probe_prompt_v004_run001_repair001.cpp"


def spore_snapshot(repo: Path, prepared: Path, original_asm: Path, candidate_asm: Path, report: Path) -> int:
    """Run inside Spore's own venv, using its native VC9 fingerprint checker."""
    for sub in ("tools/contrib", "tools/difftest", "tools/matching", "tools/ci", "tools/equiv"):
        sys.path.insert(0, str(repo / sub))
    import task as T
    import slice as S
    import fingerprint as F
    import func as FN
    from coff import Coff
    import asm_audit

    asm = asm_audit.transcribed(str(prepared)).get(f"{VA:08x}")
    if asm:
        print(f"Rejected assembly transcription: {asm}", flush=True)
        return 1

    fp = T.fingerprint(VA)
    if fp is None or not (repo / "work/SporeApp.analysis.bin").is_file():
        print("Missing retail fingerprint or analysis image", flush=True)
        return 2
    retail = FN.retail_func(VA)
    md = FN.MD
    original_asm.write_text("".join(
        f"{i.address:08x} {i.mnemonic} {i.op_str}\n" for i in md.disasm(retail.code, VA)
    ), encoding="utf-8")
    flags, _ = S.choose_flags("s00672cf0", VA)
    obj, log = S.compile_obj(str(prepared), flags)
    if obj is None:
        report.write_text(json.dumps({"status": "VC9_COMPILE_FAILED", "diagnostics": log}, indent=2))
        print("VC9 compile failed: " + (log or "")[-2000:], flush=True)
        return 1
    symbols = [s for s in Coff(obj).functions() if s.startswith(
        "?FUN_00672cf0@InklingCandidate_s00672cf0@@"
    )]
    if len(symbols) != 1:
        print(f"Unexpected candidate symbol: {symbols}", flush=True)
        return 1
    symbol = symbols[0]
    ours = FN.obj_func(obj, symbol)
    external = [v[1] for v in ours.relocs.values() if v[0] == "sym"]
    valid_callee = len(external) == 1 and external[0].startswith(
        "?FUN_00672750@InklingCandidate_s00672cf0@@"
    )
    candidate_asm.write_text("".join(
        f"{VA+i.address:08x} {i.mnemonic} {i.op_str}\n" for i in md.disasm(ours.code, 0)
    ), encoding="utf-8")

    def shape(code):
        return re.sub(r"\b(?:eax|ebx|ecx|edx|esi|edi|ebp)\b", "R",
                      re.sub(r"0x[0-9a-f]+", "N", code))
    orig_ins = [f"{i.mnemonic} {i.op_str}" for i in md.disasm(retail.code, VA)]
    ours_ins = [f"{i.mnemonic} {i.op_str}" for i in md.disasm(ours.code, 0)]
    similarity = round(difflib.SequenceMatcher(
        None, list(map(shape, orig_ins)), list(map(shape, ours_ins)), autojunk=False
    ).ratio(), 5)
    secs, syms = F.parse_coff(obj)
    data, rel = F.extract(secs, syms, symbol)
    verdict = F.check(fp, data, rel)
    result = {
        "status": "COMPILED" if verdict != "PASS" or valid_callee else "UNVERIFIED_TARGET",
        "fingerprint": verdict,
        "retail_bytes": len(retail.code), "candidate_bytes": len(ours.code),
        "retail_instructions": len(orig_ins), "candidate_instructions": len(ours_ins),
        "shape_similarity_heuristic": similarity, "object": str(obj), "symbol": symbol,
        "callee_symbol_valid": valid_callee,
        "callee_target": "0x00672750 (assumed from synthetic declaration; not independently linked)",
        "original_asm": str(original_asm), "candidate_asm": str(candidate_asm), "flags": flags,
    }
    report.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("Snapshot: " + json.dumps({k: result[k] for k in (
        "fingerprint", "retail_bytes", "candidate_bytes", "retail_instructions",
        "candidate_instructions", "shape_similarity_heuristic", "callee_symbol_valid"
    )}), flush=True)
    return 0


def snapshot(repo: Path, candidate: Path, case: Path, tag: str) -> dict:
    prepared = prepare_source(repo, candidate)
    orig = case / "c2scope_original_00672cf0.s"
    mine = case / f"{tag}.s"
    report = case / f"{tag}.snapshot.json"
    cmd = [str(repo / ".venv/bin/python"), str(Path(__file__).resolve()), "--worker-snapshot",
           "--spore-repo", str(repo), "--prepared", str(prepared),
           "--original-asm", str(orig), "--candidate-asm", str(mine), "--report", str(report)]
    proc = subprocess.run(cmd, cwd=repo, text=True, capture_output=True, timeout=180)
    (case / f"{tag}.vc9.log").write_text(proc.stdout + proc.stderr, encoding="utf-8")
    print(proc.stdout, end="", flush=True)
    if proc.returncode or not report.is_file():
        raise RuntimeError(f"VC9 snapshot failed; see {tag}.vc9.log: {proc.stderr[-500:]}")
    result = json.loads(report.read_text(encoding="utf-8"))
    if result.get("status") != "COMPILED":
        raise RuntimeError(f"VC9 result: {result.get('status')}")
    return dict(result, prepared=str(prepared), report=str(report))


def c2scope_commands(c2root: Path, source: Path, original_asm: Path, case: Path, tag: str) -> dict:
    common = ["--func", FUNC, "--c2", "15.00"]
    asm = ["--asm-vs", str(original_asm), "--asm-func", FUNC]
    flags = ["--", *FLAGS]
    return {
        "icount": ["uv", "run", "tools/icount.py", str(source), *common, *asm,
                   "--json", str(case / f"{tag}.icount.json"), "--allow-local", *flags],
        "regs": ["uv", "run", "tools/c2trace.py", "regs", str(source), *common, *flags],
        "schedwant": ["uv", "run", "tools/schedwant.py", str(source), *common, *asm,
                      "--depth", "1", *flags],
    }


def run_c2scope(c2root: Path, state: dict, case: Path, tag: str, sched: bool = True) -> dict:
    commands = c2scope_commands(c2root, Path(state["prepared"]),
                                Path(state["original_asm"]), case, tag)
    if not sched:
        commands.pop("schedwant")
    logs = {}
    env = dict(os.environ, C2TRACE_REMOTE="0", PCODE2CPP_C2SCOPE_ROOT=str(c2root))
    # The caller may have activated pcode2cpp/.venv; uv must pick c2scope/.venv.
    env.pop("VIRTUAL_ENV", None)
    merge_hook_error = re.compile(
        r"no c2 function \?(?:FgDoLateFlowOpts(?:Once)?|FgTryCommonTailMerge|"
        r"FgDoCommonTailMerge|FgMdInstrsMatch|FgTryTailMerge|"
        r"FgCrossJumpRemove|FgTryCommonHeadMerge|FgDoCommonHeadMerge|FgTryHeadMerge)"
    )
    for name, cmd in commands.items():
        log = case / f"{tag}.{name}.log"
        print(f"C2Scope {name}: {log}", flush=True)
        try:
            result = subprocess.run(cmd, cwd=c2root, env=env,
                                    capture_output=True, text=True, timeout=180, check=False)
            full = result.stdout + result.stderr
            fallback_used = False
            if name == "icount" and result.returncode and merge_hook_error.search(full):
                print(
                    "C2Scope VC9 late-flow merge hook unavailable; retrying "
                    "instruction-count analysis without optional merge hooks.",
                    flush=True,
                )
                shim = (ROOT / "scripts/c2scope_icount_fallback.py").resolve()
                if not shim.is_file():
                    raise RuntimeError(f"C2Scope fallback shim missing: {shim}")
                retry_cmd = ["uv", "run", "python", str(shim), *cmd[3:]]
                retry = subprocess.run(
                    retry_cmd, cwd=c2root, env=env,
                    capture_output=True, text=True, timeout=180, check=False,
                )
                full += (
                    "\n\n=== Retry without optional VC9 merge hooks ===\n"
                    + retry.stdout + retry.stderr
                )
                result = retry
                fallback_used = True
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.write_text(str(exc) + "\n", encoding="utf-8")
            logs[name] = {"ok": False, "log": str(log), "detail": str(exc)}
            if name == "icount":
                raise RuntimeError(f"C2Scope icount failed: {exc}") from exc
            continue
        log.write_text(full, encoding="utf-8")
        logs[name] = {
            "ok": result.returncode == 0, "log": str(log), "detail": full[-1200:],
            "fallback_without_merges": fallback_used,
        }
        if name == "icount" and result.returncode:
            raise RuntimeError(f"C2Scope icount exited {result.returncode}: {full[-1200:]}")
    return logs


def compress_feedback(state: dict, logs: dict, case: Path, tag: str) -> str:
    feedback = {
        "vc9": {k: state[k] for k in ("fingerprint", "retail_bytes", "candidate_bytes",
                                    "retail_instructions", "candidate_instructions",
                                    "shape_similarity_heuristic")},
        "c2scope": {},
    }
    path = case / f"{tag}.icount.json"
    if path.is_file():
        raw = json.loads(path.read_text(encoding="utf-8"))
        feedback["c2scope"]["icount"] = {
            "ours": raw.get("ours"), "original": raw.get("orig"),
            "runs": [{"kind": r.get("kind"), "source_line": r.get("line"),
                      "source": r.get("src"), "verdict": r.get("verdict"),
                      "lever": r.get("lever"),
                      "items": [{"asm": i.get("ins"), "verdict": i.get("verdict"),
                                 "origin": i.get("origin"), "why": i.get("why")}
                                for i in r.get("items", [])[:5]]}
                     for r in raw.get("runs", [])[:15]],
            "hints": raw.get("hints", [])[:5],
            "lift": {k: raw["lift"].get(k) for k in ("self", "n", "text", "error")}
                    if isinstance(raw.get("lift"), dict) else None,
        }
    for name in ("regs", "schedwant"):
        entry = logs.get(name)
        if entry and entry["ok"]:
            feedback["c2scope"][name] = Path(entry["log"]).read_text(encoding="utf-8")[:9000]
        elif entry:
            feedback["c2scope"][name + "_status"] = "unavailable: " + entry["detail"][-300:]
    return json.dumps(feedback, indent=2)


def make_messages(body: str, original: str, candidate: str, feedback: str) -> list[dict]:
    return [
        {"role": "system", "content": (
            "You are tuning C++ source to reproduce MSVC 2008 SP1 (VC9/C2 15.00) x86 code. "
            "Preserve all program behavior, memory effects, call arguments, return and calling convention. "
            "Use observed C2Scope traces and register/scheduler information, not generic compiler guesses. "
            "Prefer one minimal source-level rewrite per response. "
            "No inline assembly, byte literals, fake call addresses or hardcoded source pointers. "
            "The fixed C++ prefix and synthetic member-function VC9 wrapper cannot be edited. "
            "Return ONLY schema JSON with one string field 'body' containing complete revised C++ statements "
            "without braces or commentary."
        )},
        {"role": "user", "content": (
            "Target Spore function 0x00672cf0, VC9 /O2 /MD /Gy /EHsc /TP. "
            "The baseline passed 220 valid Unicorn differential executions, "
            "but angr refuted call-time ESP equality and the bytes do not match. "
            "Keep the original behavior and synthetic callee identity.\n\n"
            "Existing body:\n" + body + "\n\n"
            "Original retail disassembly:\n" + original + "\n\n"
            "Current VC9 disassembly:\n" + candidate + "\n\n"
            "C2Scope findings from the actual compiler:\n" + feedback + "\n\n"
            "Attempt one source-level byte-match improvement. Do not change the fixed source prefix."
        )},
    ]


def stream_model(cfg: dict, messages: list[dict], log: Path, max_tokens: int) -> str:
    payload = {
        "model": cfg.get("model", "local"), "messages": messages,
        "temperature": cfg.get("temperature", 0), "max_tokens": max_tokens,
        "stream": True, "response_format": {"type": "json_schema", "schema": SCHEMA},
    }
    req = Request(cfg.get("url", "http://127.0.0.1:8080/v1/chat/completions"),
                  data=json.dumps(payload).encode("utf-8"),
                  headers={"Content-Type": "application/json"})
    parts, finish, section = [], None, None
    try:
        with urlopen(req, timeout=cfg.get("timeout_seconds", 1800)) as response:
            with log.open("x", encoding="utf-8") as sink:
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
                        for typ, text in (("Reasoning", delta.get("reasoning_content") or delta.get("reasoning") or ""),
                                          ("JSON", delta.get("content") or "")):
                            if not text:
                                continue
                            if section != typ:
                                section = typ
                                print(f"\n[{typ}]\n", flush=True)
                                sink.write(f"\n[{typ}]\n")
                            sink.write(text)
                            sink.flush()
                            print(text, end="", flush=True)
                            if typ == "JSON":
                                parts.append(text)
                        finish = choice.get("finish_reason") or finish
    except HTTPError as exc:
        raise RuntimeError(f"llama.cpp rejected request ({exc.code}): " +
                           exc.read().decode("utf-8", errors="replace")) from exc
    except URLError as exc:
        raise RuntimeError(f"llama.cpp connection failed: {exc}") from exc
    print(f"\nFinish reason: {finish}; transcript: {log}", flush=True)
    if not parts or finish not in (None, "stop"):
        raise RuntimeError("Model output missing or truncated; no candidate accepted")
    try:
        body = json.loads("".join(parts))["body"]
    except (ValueError, TypeError, KeyError) as exc:
        raise RuntimeError(f"Invalid model response: {exc}") from exc
    if not isinstance(body, str) or not body.strip():
        raise RuntimeError("Model returned empty/non-string body")
    return body


def differential_test(repo: Path, prepared: str, case: Path, tag: str, attempts: int) -> dict:
    result_json = case / f"{tag}.unicorn.json"
    cmd = [str(repo / ".venv/bin/python"), "tools/difftest/equiv.py", "s00672cf0", "00672cf0",
           "--src", prepared, "--inputs", str(attempts), "--min-valid", "200",
           "--plateau", "0", "--time-limit", "120", "--json", str(result_json)]
    proc = subprocess.run(cmd, cwd=repo, capture_output=True, text=True, timeout=180, check=False)
    (case / f"{tag}.unicorn.log").write_text(proc.stdout + proc.stderr, encoding="utf-8")
    if not result_json.is_file():
        return {"verdict": "ERROR", "reason": (proc.stdout + proc.stderr)[-500:]}
    try:
        row = json.loads(result_json.read_text(encoding="utf-8"))[0]
        return {"verdict": row.get("verdict", "ERROR"), "reason": row.get("reason", ""),
                "valid": row.get("valid")}
    except (ValueError, IndexError, TypeError) as exc:
        return {"verdict": "ERROR", "reason": str(exc)}


def formal_test(repo: Path, candidate: Path, case: Path, tag: str, timeout: int) -> str:
    cmd = [str(repo / ".venv/bin/python"), str((ROOT / "scripts/prove_spore_candidate.py").resolve()),
           str(candidate), "--spore-repo", str(repo), "--timeout", str(timeout)]
    proc = subprocess.run(cmd, cwd=repo, capture_output=True, text=True,
                          timeout=timeout * 8 + 90, check=False)
    output = proc.stdout + proc.stderr
    (case / f"{tag}.formal.log").write_text(output, encoding="utf-8")
    m = re.search(r"(?m)^(MATCH|EQUIVALENT|REFUTED|UNKNOWN) 0x00672cf0\b", output)
    return m.group(1) if m else "ERROR"


def run(args) -> int:
    candidate = args.candidate.expanduser().resolve()
    parent = candidate.parent / "c2scope_runs"
    parent.mkdir(exist_ok=True)
    for n in range(1, 10000):
        case = parent / f"run{n:03d}"
        try:
            case.mkdir(exist_ok=False)
            break
        except FileExistsError:
            continue
    else:
        raise RuntimeError("No free experiment directory")
    print(f"Experiment artifacts: {case}", flush=True)
    if not candidate.is_file():
        raise ValueError(f"Candidate missing: {candidate}")
    config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
    repo = (args.spore_repo or Path(config["spore"]["repo_path"])).expanduser().resolve()
    c2root = args.c2scope_repo.expanduser().resolve()
    if not (repo / "tools/contrib/check.py").is_file() or not (repo / ".venv/bin/python").is_file():
        raise ValueError(f"Spore toolchain unavailable at {repo}")
    if not (c2root / "tools/icount.py").is_file():
        raise ValueError(f"C2Scope not found at {c2root}")
    if check_candidate(candidate).status != "PASS":
        raise ValueError("Starting candidate must pass Clang; use repair_candidate.py first")
    state = snapshot(repo, candidate, case, "c2scope_base")
    print("Initial fingerprint verdict: " + state["fingerprint"], flush=True)
    if state["fingerprint"] == "PASS":
        print("Already byte-exact; no inference needed", flush=True)
        return 0
    seen = {hashlib.sha256(candidate.read_bytes()).hexdigest()}
    model_cfg = config["llm"]
    history = []
    for round_no in range(1, args.rounds + 1):
        tag = f"{args.candidate.stem}_c2scope_{round_no:03d}"
        previous_tag = "c2scope_base" if round_no == 1 else f"{args.candidate.stem}_c2scope_{round_no-1:03d}"
        print(f"\n===== C2Scope feedback, round {round_no}/{args.rounds} =====", flush=True)
        logs = run_c2scope(c2root, state, case, previous_tag, sched=not args.no_schedwant)
        feedback = compress_feedback(state, logs, case, previous_tag)
        messages = make_messages(extract_body(candidate.read_text(encoding="utf-8")),
                                 Path(state["original_asm"]).read_text(encoding="utf-8"),
                                 Path(state["candidate_asm"]).read_text(encoding="utf-8"), feedback)
        prompt_path = case / f"{tag}.feedback.json"
        prompt_path.write_text(json.dumps({"candidate": str(candidate), "messages": messages,
                                          "c2scope_logs": logs}, indent=2), encoding="utf-8")
        if args.dry_run:
            print(f"Feedback prepared without inference: {prompt_path}", flush=True)
            return 0
        body = stream_model(model_cfg, messages, case / f"{tag}.llm.log",
                            args.max_tokens if args.max_tokens is not None else model_cfg.get("max_tokens", 32768))
        if re.search(r"\b(?:__asm|_asm|asm|__emit|_emit)\b|__declspec\s*\(\s*naked\s*\)|^\s*#(?:include|pragma)", body, re.I | re.M):
            print("Rejected inline assembly, naked function, or directive in model output", flush=True)
            return 1
        new_path = case / f"{tag}.cpp"
        source = PREFIX + body.strip("\n") + "\n}\n"
        with new_path.open("x", encoding="utf-8") as handle:
            handle.write(source)
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        if digest in seen:
            print("Model repeated an earlier candidate, stopping to avoid duplicate inference", flush=True)
            return 1
        seen.add(digest)
        clang = check_candidate(new_path)
        if not clang.passed:
            print(f"Round {round_no}: Clang {clang.status}, source kept for inspection\n{clang.diagnostics}")
            return 1
        try:
            updated = snapshot(repo, new_path, case, tag)
        except Exception as exc:
            print(f"Round {round_no}: VC9 check failed: {exc}")
            return 1
        delta = round(updated["shape_similarity_heuristic"] - state["shape_similarity_heuristic"], 5)
        print(f"Round {round_no} VC9: {updated['fingerprint']}, "
              f"{updated['candidate_bytes']} bytes, shape score {updated['shape_similarity_heuristic']} "
              f"(delta {delta:+.5f}, heuristic only)", flush=True)
        if updated["fingerprint"] != "PASS":
            empirical = differential_test(repo, updated["prepared"], case, tag, args.inputs)
            print(f"Unicorn: {empirical}", flush=True)
            if empirical["verdict"] != "PASS":
                print("Not empirically validated, candidate retained but not selected for the next round", flush=True)
                return 1
        proof = formal_test(repo, new_path, case, tag, args.proof_timeout)
        print(f"Formal Spore prover: {proof} (see {tag}.formal.log)", flush=True)
        history.append({"round": round_no, "candidate": str(new_path),
                        "fingerprint": updated["fingerprint"], "formal": proof,
                        "score": updated["shape_similarity_heuristic"]})
        (case / f"{args.candidate.stem}_c2scope_summary.json").write_text(
            json.dumps(history, indent=2), encoding="utf-8")
        if updated["fingerprint"] == "PASS":
            print("BYTE-EXACT fingerprint shape. Synthetic callee linkage remains an assumption.", flush=True)
            return 0 if proof in ("MATCH", "EQUIVALENT") else 1
        candidate, state = new_path, updated
    print("Experiment exhausted without byte-exact match. Candidates and logs retained.", flush=True)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", nargs="?", type=Path, default=DEFAULT_CANDIDATE)
    parser.add_argument("--spore-repo", type=Path)
    parser.add_argument("--c2scope-repo", type=Path, default=Path.home() / "c2scope")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--max-tokens", type=int, default=None, help="Override config.json max_tokens")
    parser.add_argument("--inputs", type=int, default=700)
    parser.add_argument("--proof-timeout", type=int, default=90)
    parser.add_argument("--dry-run", action="store_true", help="Gather real C2Scope evidence, no model request")
    parser.add_argument("--no-schedwant", action="store_true", help="Skip optional scheduler inversions")
    parser.add_argument("--worker-snapshot", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--prepared", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--original-asm", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--candidate-asm", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--report", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker_snapshot:
        if not all((args.spore_repo, args.prepared, args.original_asm, args.candidate_asm, args.report)):
            parser.error("Worker requires source, repo and output paths")
        repo = args.spore_repo.expanduser().resolve()
        prepared = args.prepared.resolve()
        if not prepared.is_relative_to((repo / "work/pcode2cpp_checks").resolve()):
            parser.error("Worker only accepts ignored Spore work sources")
        return spore_snapshot(repo, prepared, args.original_asm, args.candidate_asm, args.report)
    if args.rounds < 1 or (args.max_tokens is not None and args.max_tokens < 1) or args.inputs < 200 or args.proof_timeout < 1:
        parser.error("rounds/max-tokens/proof-timeout must be positive and inputs >=200")
    try:
        return run(args)
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"Experiment stopped: {exc}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
