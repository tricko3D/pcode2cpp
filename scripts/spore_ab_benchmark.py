#!/usr/bin/env python3
"""Compare Codex refinements from the same initial pcode2cpp pipeline candidate.

For a new function the established run_pipeline.py's VC9/Unicorn/angr adapter
does not apply. This runner uses pcode2cpp's Ghidra/prompt/model components,
then the Spore check.py verifier and bounded C2Scope sweeps. It is an
EXPERIMENTAL GENERALIZED pipeline, not the 0x00672cf0 adapter.
Run on the WSL host with Spore, Ghidra, Codex CLI and C2Scope installed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pcode2cpp.ghidra import export_function
from scripts import auto_match as A
from scripts import build_prompt as BP
from scripts.model_client import chat_json, load_profile
from scripts.select_large_spore import select

BASE = ROOT / "cases/spore-ab"
MODEL = "gpt-6.2-sol"
TIME_BUDGET = 7200


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def command(argv, *, cwd=None, stdin=None, timeout=1200, env=None):
    return subprocess.run(argv, cwd=cwd, text=True, input=stdin, timeout=timeout,
                          capture_output=True, env=env, check=False)


def snapshot_limits():
    root = Path.home() / ".codex/sessions"
    if not root.is_dir():
        return None
    files = sorted(root.rglob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)[:30]
    found = []
    for p in files:
        try:
            for line in p.open(encoding="utf-8", errors="replace"):
                event = json.loads(line)
                body = event.get("payload") or {}
                if body.get("type") == "token_count" and body.get("rate_limits"):
                    found.append({"timestamp": event.get("timestamp", ""),
                                  "session_file": p.name, "limits": body["rate_limits"]})
        except (ValueError, OSError):
            continue
    return max(found, key=lambda x: x["timestamp"]) if found else None


def allowance(before, after):
    output = {}
    if not before or not after:
        return {"unavailable": "No Codex rate-limit snapshot"}
    if before.get("timestamp") is not None and before["timestamp"] == after.get("timestamp"):
        return {"unavailable": "No fresh Codex limit snapshot after this run"}
    for window in ("primary", "secondary"):
        b = before["limits"].get(window) or {}
        a = after["limits"].get(window) or {}
        if b.get("resets_at") != a.get("resets_at"):
            output[window] = {"unavailable": "Allowance reset during run"}
        elif "used_percent" in a and "used_percent" in b:
            output[window] = {
                "window_minutes": a.get("window_minutes"),
                "used_before": b["used_percent"],
                "used_after": a["used_percent"],
                "estimated_percentage_point_change": round(a["used_percent"] - b["used_percent"], 3),
                "rounded": True,
            }
    return output


def checkout_archive(spore, destination):
    destination.mkdir(parents=True, exist_ok=False)
    archive = subprocess.Popen(["git", "archive", "--format=tar", "HEAD"],
                               cwd=spore, stdout=subprocess.PIPE)
    extract = subprocess.run(["tar", "-x", "-C", str(destination)],
                             stdin=archive.stdout, capture_output=True, text=True)
    archive.stdout.close()
    rc = archive.wait()
    if rc or extract.returncode:
        raise RuntimeError(f"Archive error, git={rc}: {extract.stderr}")
    (destination / "work").mkdir(exist_ok=True)
    for item in ("toolchain", "oss", "SporeApp.analysis.bin"):
        existing = spore / "work" / item
        if existing.exists():
            (destination / "work" / item).symlink_to(
                existing, target_is_directory=existing.is_dir())
    if (spore / ".venv").is_dir():
        (destination / ".venv").symlink_to(spore / ".venv", target_is_directory=True)


def experiment_dir(address):
    return BASE / f"{int(address, 16):08x}"


def prepare(args):
    spore = args.spore.expanduser().resolve()
    candidates = select(spore, args.min_bytes, args.max_bytes)
    if not candidates:
        raise RuntimeError("No unimplemented unclaimed functions in requested size range")
    if args.address:
        selected = next((x for x in candidates if int(x["address"], 16) ==
                         int(args.address, 16)), None)
        if selected is None:
            raise RuntimeError("Address is not among verified unimplemented candidates")
    else:
        selected = candidates[0]
    address = selected["address"]
    base = experiment_dir(address)
    if base.exists():
        raise RuntimeError(f"Experiment exists: {base}; refusing to overwrite")
    base.mkdir(parents=True)
    try:
        # Git archive always uses committed HEAD, never uncommitted working-tree
        # sources. Warn but do not block contributors with unrelated local edits.
        dirty = command(["git", "status", "--porcelain", "--untracked-files=no"], cwd=spore)
        if dirty.returncode:
            raise RuntimeError("Cannot inspect Spore source state: " + dirty.stderr[-1000:])
        if dirty.stdout.strip():
            print("Note: ignored uncommitted Spore edits; both arms archive HEAD.", flush=True)
        settings = read(ROOT / "config.json")
        print(f"Exporting original Ghidra evidence for {address} ({selected['retail_bytes']} bytes)", flush=True)
        ctx_file = base / "context.json"
        ctx = export_function(int(address, 16), ctx_file, settings["ghidra"])
        callees, missing = BP.read_direct_callees(ctx, ROOT / "data/retail-contexts")
        evidence = BP.render_prompt(ctx, "Reconstruct the retail Spore function from the evidence.",
                                    callees, missing)
        rules = (spore / "AGENTS.md").read_text(encoding="utf-8")
        common = (
            f"Target function: {address}. Retail size: {selected['retail_bytes']} bytes.\n"
            "Goal: an exact VC9 byte match, not only equivalent behavior.\n"
            "The target has no implementation in this source snapshot.\n"
            "Do not search history, retrieve upstream solutions, or copy known matching code.\n\n"
            "Full repository instructions:\n" + rules +
            "\n\nComplete original Ghidra context:\n" + evidence
        )
        (base / "evidence.md").write_text(common, encoding="utf-8")
        commit = command(["git", "rev-parse", "HEAD"], cwd=spore)
        if commit.returncode:
            raise RuntimeError(commit.stderr)
        relpath = f"match/slices/s{int(address,16):08x}/s{int(address,16):08x}.cpp"
        for arm in ("pipeline", "isolated", "agent"):
            target_dir = base / arm / "spore"
            target_dir.parent.mkdir(parents=True)
            checkout_archive(spore, target_dir)
            target_file = target_dir / relpath
            if target_file.exists():
                raise RuntimeError(f"Target file unexpectedly exists: {target_file}")
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_text(f"// @ {address}\n// No implementation yet.\n")
            scratch = target_dir / "work/scratch"
            scratch.mkdir(parents=True, exist_ok=True)
            (scratch / "evidence.md").write_text(common, encoding="utf-8")
            # Negative control: all arms initially lack a source implementation.
            baseline = verify(target_dir, address, target_dir.parent / "baseline_check.log")
            if baseline["match"]:
                raise RuntimeError(f"Pre-run baseline unexpectedly matches: {target_dir}")
            save(target_dir.parent / "baseline_check.json", baseline)
        info = {
            "target": selected,
            "model": MODEL,
            "baseline_commit": commit.stdout.strip(),
            "source_worktree_had_uncommitted_edits": bool(dirty.stdout.strip()),
            "context_sha256": sha(ctx_file.read_bytes()),
            "evidence_sha256": sha(common.encode("utf-8")),
            "target_source": relpath,
            "setup_date_unix": time.time(),
            "stages": ["shared-pipeline", "isolated-final-refinement", "agentic-final-refinement"],
            "tool_free_rounds": args.rounds,
            "c2scope_limit": args.sweep_limit,
            "wall_time_budget_seconds_per_arm": TIME_BUDGET,
        }
        save(base / "experiment.json", info)
        print(f"Selected {address}, {selected['retail_bytes']} bytes")
        print("Evidence and baseline saved:", base)
        print("No agent or model has been run yet.")
        return address

    except Exception:
        # A failed Ghidra export or checkout setup must not poison the target.
        shutil.rmtree(base, ignore_errors=True)
        raise

def load_arm(address, arm):
    base = experiment_dir(address)
    info = read(base / "experiment.json")
    if int(info["target"]["address"], 16) != int(address, 16):
        raise ValueError("Experiment address does not match metadata")
    checkout = base / arm / "spore"
    return base, info, checkout, checkout / info["target_source"]



def handoff_to_refinement(base, info, arm):
    """Install the exact same completed pipeline source in either refinement arm."""
    previous_file = base / "pipeline/result.json"
    handoff = base / "pipeline/handoff.cpp"
    if not previous_file.is_file() or not handoff.is_file():
        raise RuntimeError("Run the pipeline first: no candidate handoff exists")
    previous = read(previous_file)
    contents = handoff.read_bytes()
    digest = sha(contents)
    if previous.get("handoff_sha256") != digest:
        raise RuntimeError("Recorded pipeline handoff has changed")
    if not previous.get("pipeline_complete"):
        raise RuntimeError("Mechanical matching stage incomplete, refusing Codex refinement")
    if previous.get("match"):
        raise RuntimeError("pcode2cpp already achieved byte MATCH; no Codex refinement needed")
    checkout = base / arm / "spore"
    source = checkout / info["target_source"]
    expected = f"// @ {info['target']['address']}\n// No implementation yet.\n"
    if source.read_text(encoding="utf-8") != expected:
        raise RuntimeError(f"Refinement source is not pristine: {source}")
    source.write_bytes(contents)
    feedback = (previous.get("handoff_verification") or {}).get("feedback", "")
    prompt = (
        f"Target: {info['target']['address']} ({info['target']['retail_bytes']} retail bytes).\n"
        "The target C++ file contains the candidate produced by pcode2cpp. "
        "IMPROVE it toward a VC9 byte-exact MATCH, not equivalence. "
        "Preserve observable semantics, ABI and calls. "
        "Do not inspect history or retrieve an existing solution.\n\n"
        "Final pipeline compiler and fingerprint feedback:\n" + feedback
    )
    scratch = checkout / "work/scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    (scratch / "refine_prompt.md").write_text(prompt, encoding="utf-8")
    return digest, prompt


def verify(checkout, address, path):
    p = command([str(checkout / ".venv/bin/python"),
                 "tools/contrib/check.py", address, "--no-quick", "--dry-run"],
                cwd=checkout, timeout=900)
    result = p.stdout + p.stderr
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result, encoding="utf-8")
    pattern = r"(?m)^MATCH\s+0x[0-9a-f]+\b"
    symbol = re.search(r"(?m)^(?:NO )?MATCH\s+0x[0-9a-f]+\s+(\S+)", result, re.I)
    flags = re.search(r"(?m)^(?:NO )?MATCH\s+0x[0-9a-f]+.*?\[([^\]]+)\]", result, re.I)
    return {"match": bool(re.search(pattern, result, re.I)),
            "symbol": symbol.group(1) if symbol else None,
            "compiler_flags": flags.group(1).split() if flags else None,
            "exit": p.returncode, "log": str(path),
            "feedback": result[-9000:]}


def retail_assembly(checkout, address, output):
    script = (
        "import sys; from pathlib import Path; repo=Path('.').resolve(); "
        "sys.path[:0]=[str(repo/x) for x in ('tools/difftest','tools/matching')]; "
        "import func as F; va=int(sys.argv[1],16); fn=F.retail_func(va); "
        "lines=[f'{i.address:08x} {i.mnemonic} {i.op_str}' for i in F.MD.disasm(fn.code,va)]; "
        "Path(sys.argv[2]).write_text('\\n'.join(lines)+'\\n')"
    )
    p = command([str(checkout / ".venv/bin/python"), "-c", script,
                 address, str(output)], cwd=checkout)
    if p.returncode:
        raise RuntimeError("Cannot read original assembly: " + p.stderr[-1200:])


def mechanical(checkout, address, source, symbol, folder, workers, limit, flags):
    folder.mkdir(parents=True, exist_ok=True)
    # C2Scope runs from its own repository, so Spore-relative include flags
    # must become absolute while keeping the actual VC9 optimization flags.
    native_flags = []
    for flag in flags:
        if flag.startswith("/I") and len(flag) > 2:
            include = Path(flag[2:])
            if not include.is_absolute():
                include = checkout / include
            native_flags.append("/I" + str(include))
        else:
            native_flags.append(flag)
    asm = folder / "original.s"
    retail_assembly(checkout, address, asm)
    cmd = [
        "uv", "run", "tools/rwsweep.py", str(source),
        "--func", symbol, "--asm-vs", str(asm),
        "--families", A.DEFAULT_FAMILIES, "--jobs", str(workers),
        "--limit", str(limit), "--max-combo", "2", "--verify", "8",
        "--c2", "15.00", "--", *native_flags
    ]
    env = os.environ.copy()
    env["C2TRACE_REMOTE"] = "0"
    env.pop("VIRTUAL_ENV", None)
    p = command(cmd, cwd=Path.home() / "c2scope", timeout=1800, env=env)
    (folder / "rwsweep.log").write_text(p.stdout + p.stderr)
    if p.returncode:
        raise RuntimeError("C2Scope sweep failed, see " + str(folder / "rwsweep.log"))
    _, ranked, count = A.parse_sweep(p.stdout + p.stderr)
    return ranked[:6], count


def pipeline(args):
    base, info, checkout, source = load_arm(args.address, "pipeline")
    destination = base / "pipeline/result.json"
    if destination.exists():
        raise RuntimeError("Pipeline already recorded; refusing to overwrite")
    profile = load_profile(ROOT / "config.model-profiles.example.json", "codex-plus")
    profile["model"] = MODEL
    evidence = (base / "evidence.md").read_text()
    address = info["target"]["address"]
    logs = base / "pipeline/logs"
    logs.mkdir(parents=True, exist_ok=True)
    tokens, trials = [], []
    before = snapshot_limits()
    t0 = time.time()
    matched, failure = False, None
    feedback = ""
    best_source, best_score = None, None
    c2scope_attempts = 0
    c2scope_completed = 0
    c2scope_skipped = 0
    c2scope_errors = 0
    try:
        for n in range(args.rounds):
            remaining = TIME_BUDGET - (time.time() - t0)
            if remaining <= 0:
                break
            profile["timeout_seconds"] = max(1, min(1800, int(remaining)))
            if n == 0:
                system = ("Reconstruct a complete valid Visual C++ 2008 C++ translation unit "
                          "using Ghidra evidence. Return JSON with one body string containing "
                          "the entire .cpp source, not only a function body.")
                request = evidence + "\n\nSource must include the line // @ " + address + \
                    " immediately before the target function. No assembly, stubs or placeholders."
            else:
                system = ("Repair or improve the entire C++ source to achieve a byte-exact "
                          "VC9 result. Return JSON with one body string containing the full .cpp.")
                request = (evidence + "\n\nCurrent source:\n" + source.read_text() +
                           "\n\nVerifier feedback:\n" + feedback)
            output, meta = chat_json(profile, [
                {"role": "system", "content": system},
                {"role": "user", "content": request},
            ])
            tokens.append(meta)
            cpp = output.get("body")
            if not isinstance(cpp, str) or not cpp.strip():
                raise ValueError("Model returned no source")
            if "// @ " + address not in cpp:
                raise ValueError("Model did not include required address marker")
            if re.search(r"(?im)\b(?:__asm|_asm|asm)\b|__declspec\s*\(\s*naked\s*\)", cpp):
                raise ValueError("Inline assembly is forbidden")
            source.write_text(cpp.rstrip() + "\n")
            (logs / f"candidate_{n:02d}.cpp").write_text(cpp.rstrip() + "\n")
            result = verify(checkout, address, logs / f"check_{n:02d}.log")
            trials.append({"round": n, "kind": "model", "source_sha256": sha(cpp.encode()), **result})
            if result["match"]:
                print(f"Pipeline model round {n + 1}: byte-exact MATCH, C2Scope unnecessary", flush=True)
                matched = True
                break
            feedback = result["feedback"]
            if args.sweep_limit == 0:
                why = "disabled by --sweep-limit 0"
            elif not result["symbol"]:
                why = "no compiled function symbol (probably compile failed); check " + result["log"]
            elif not result["compiler_flags"]:
                why = "no compiler flags parsed; check " + result["log"]
            else:
                why = None
            if why:
                c2scope_skipped += 1
                trials.append({"round": n, "kind": "c2scope_skipped", "reason": why})
                print(f"Pipeline round {n + 1}: no MATCH; C2Scope SKIPPED: {why}",
                      flush=True)
                continue

            print(f"Pipeline round {n + 1}: no MATCH; starting C2Scope "
                  f"({args.sweep_limit} variants max, {args.workers} workers)",
                  flush=True)
            c2scope_attempts += 1
            try:
                folder = logs / f"c2scope_{n:02d}"
                ranked, count = mechanical(
                    checkout, address, source, result["symbol"], folder,
                    args.workers, args.sweep_limit, result["compiler_flags"])
                trials.append({"round": n, "kind": "c2scope", "measured": count,
                               "ranked_scores": [[name, rd, bd] for name, rd, bd, _ in ranked]})
                print(f"Pipeline round {n + 1}: C2Scope measured {count} variants; "
                      f"checking {len(ranked)} promising candidates",
                      flush=True)
                if count > 0:
                    c2scope_completed += 1
                else:
                    c2scope_errors += 1
                    trials.append({"round": n, "kind": "c2scope_error",
                                   "error": "C2Scope returned no measured variants",
                                   "log": str(folder / "rwsweep.log")})
                    print(f"Pipeline round {n + 1}: C2Scope returned NO measured variants; "
                          f"see {folder / 'rwsweep.log'}", flush=True)
                for i, (name, rd, bd, path) in enumerate(ranked):
                    if not path.is_file():
                        continue
                    source.write_bytes(path.read_bytes())
                    v = verify(checkout, address, folder / f"candidate_{i}.log")
                    trials.append({"round": n, "kind": "c2scope_check",
                                   "variant": name, "rdiff": rd, "bdiff": bd, **v})
                    if v["match"]:
                        matched = True
                        print(f"Pipeline round {n + 1}: C2Scope candidate {name} MATCH",
                              flush=True)
                        break
                    if v["symbol"] and (best_score is None or (rd, bd) < best_score):
                        best_score, best_source = (rd, bd), source.read_bytes()
                if matched:
                    break
                source.write_text(cpp.rstrip() + "\n")
                feedback += "\nC2Scope measured:\n" + json.dumps(
                    [{"name": x[0], "rdiff": x[1], "bdiff": x[2]} for x in ranked])
            except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
                c2scope_errors += 1
                detail = str(e)
                trials.append({"round": n, "kind": "c2scope_error", "error": detail})
                print(f"Pipeline round {n + 1}: C2Scope FAILED: {detail}", flush=True)
                source.write_text(cpp.rstrip() + "\n")
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
        failure = str(e)
    # Preserve a compiler-verified improvement as the shared handoff.
    if not matched and best_source is not None:
        source.write_bytes(best_source)
    # Never hand off a reconstruction that silently omitted the mechanical
    # stage. A full byte MATCH before C2Scope is the only legitimate exception.
    pipeline_complete = matched or c2scope_completed > 0
    if not pipeline_complete:
        failure = (failure or "C2Scope did not successfully measure any variants. "
                   "The reconstruction pipeline is incomplete; Codex refinements "
                   "are blocked to avoid invalid usage comparisons.")
        print("PIPELINE INCOMPLETE: " + failure, flush=True)
    handoff_sha = None
    handoff_verification = None
    if pipeline_complete and any(x.get("kind") == "model" for x in trials) and source.is_file():
        handoff_verification = verify(checkout, address, base / "pipeline/handoff-check.log")
        if handoff_verification["symbol"] or handoff_verification["match"]:
            handoff = base / "pipeline/handoff.cpp"
            handoff.write_bytes(source.read_bytes())
            handoff_sha = sha(handoff.read_bytes())
            matched = matched or handoff_verification["match"]
    after = snapshot_limits()
    totals = {
        key: sum((u.get("usage") or {}).get(key, 0) for u in tokens)
        for key in ("input_tokens", "cached_input_tokens", "output_tokens")
    }
    save(destination, {
        "arm": "pipeline", "model": MODEL, "match": matched, "error": failure,
        "pipeline_complete": pipeline_complete,
        "c2scope_attempts": c2scope_attempts,
        "c2scope_completed": c2scope_completed,
        "c2scope_skipped": c2scope_skipped,
        "c2scope_errors": c2scope_errors,
        "handoff_sha256": handoff_sha, "handoff_verification": handoff_verification,
        "best_c2scope_score": list(best_score) if best_score is not None else None,
        "total_tokens": totals, "model_calls": tokens, "attempts": trials,
        "source_sha256": sha(source.read_bytes()) if source.is_file() else None, "seconds": time.time() - t0,
        "allowance_before": before, "allowance_after": after,
        "allowance_change": allowance(before, after),
    })
    if handoff_sha:
        print("Shared pipeline handoff SHA256:", handoff_sha, flush=True)
    else:
        print("No compiler-valid pipeline candidate available for refinement.", flush=True)
    print("Saved:", destination)


def isolated(args):
    """One tool-free Codex FINAL refinement of the shared pcode2cpp candidate."""
    base, info, checkout, source = load_arm(args.address, "isolated")
    destination = base / "isolated/result.json"
    if destination.exists():
        raise RuntimeError("Isolated refinement already recorded")
    handoff_hash, refinement = handoff_to_refinement(base, info, "isolated")
    profile = load_profile(ROOT / "config.model-profiles.example.json", "codex-plus")
    profile["model"] = MODEL
    original_cpp = source.read_text(encoding="utf-8")
    evidence = (base / "evidence.md").read_text(encoding="utf-8")
    address = info["target"]["address"]
    before = snapshot_limits()
    t0 = time.time()
    failure, usage = None, {}
    try:
        response, usage = chat_json(profile, [
            {"role": "system", "content":
             "You are the final source-refinement stage of a native C++ "
             "decompilation pipeline. Improve the supplied candidate rather "
             "than starting from scratch. No filesystem, shell, compiler, "
             "web or other tools. Return JSON with the key body containing "
             "the improved complete VC9-compatible translation unit."},
            {"role": "user", "content":
             refinement + "\n\nComplete Ghidra evidence and repository rules:\n" +
             evidence + "\n\nExact pcode2cpp pipeline candidate:\n" +
             original_cpp + "\n\nReturn the complete improved C++ with marker // @ " +
             address + " immediately before the target function."},
        ])
        cpp = response.get("body")
        if not isinstance(cpp, str) or not cpp.strip():
            raise RuntimeError("Isolated Codex returned no candidate")
        if "// @ " + address not in cpp:
            raise RuntimeError("Isolated candidate missing required address marker")
        if re.search(r"(?im)\b(?:__asm|_asm|asm)\b|__declspec\s*\(\s*naked\s*\)", cpp):
            raise RuntimeError("Isolated candidate uses forbidden assembly")
        source.write_text(cpp.rstrip() + "\n", encoding="utf-8")
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as e:
        failure = str(e)
    verdict = verify(checkout, address, base / "isolated/final-check.log")
    after = snapshot_limits()
    save(destination, {
        "arm": "isolated", "model": MODEL, "match": verdict["match"],
        "verification": verdict, "error": failure,
        "starting_source_sha256": handoff_hash,
        "source_sha256": sha(source.read_bytes()) if source.is_file() else None,
        "total_tokens": (usage.get("usage") or {}),
        "model_calls": [usage] if usage else [],
        "seconds": time.time() - t0,
        "allowance_before": before, "allowance_after": after,
        "allowance_change": allowance(before, after),
    })
    print("Isolated final refinement:", "MATCH" if verdict["match"] else "NO MATCH")
    print("Saved:", destination)


def agent(args):
    base, info, checkout, source = load_arm(args.address, "agent")
    destination = base / "agent/result.json"
    if destination.exists():
        raise RuntimeError("Agent already recorded; refusing to overwrite")
    handoff_hash, _ = handoff_to_refinement(base, info, "agent")
    address = info["target"]["address"]
    prompt = (
        "Read AGENTS.md, work/scratch/evidence.md and work/scratch/refine_prompt.md. "
        "This is a Spore byte-matching experiment for " + address + ". "
        "Refine the existing pcode2cpp candidate in " + info["target_source"] + ". "
        "You receive exactly the same Ghidra evidence used by the model-only arm. "
        "Achieve a BYTE-EXACT MATCH, not just equivalence. "
        "Use the existing VC9/check.py, C2Scope and other local verification tools. "
        "Do not use git history, web searches, or upstream matching implementations. "
        "Do not modify unrelated tracked files, do not commit. "
        "Only say MATCH if the checker prints MATCH."
    )
    before = snapshot_limits()
    t0 = time.time()
    cmd = ["codex", "exec", "--model", MODEL, "--json",
           "--skip-git-repo-check", "--sandbox", "danger-full-access", "-"]
    try:
        p = command(cmd, cwd=checkout, stdin=prompt, timeout=TIME_BUDGET)
        stdout, stderr, rc = p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        rc = 124
    (base / "agent/codex.jsonl").write_text(stdout)
    (base / "agent/codex.stderr.log").write_text(stderr)
    turns, tools = [], 0
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        item = event.get("item") or {}
        if event.get("type") == "turn.completed":
            turns.append(event.get("usage") or {})
        if event.get("type") == "item.started" and item.get("type") in (
                "command_execution", "file_change", "mcp_tool_call", "web_search"):
            tools += 1
    # Independent final compiler/fingerprint check.
    final = verify(checkout, address, base / "agent/final-check.log")
    after = snapshot_limits()
    save(destination, {
        "arm": "agent", "model": MODEL, "match": final["match"],
        "verification": final, "exit": rc, "stderr_tail": stderr[-1000:],
        "starting_source_sha256": handoff_hash,
        "total_tokens": turns[-1] if turns else {},
        "all_turn_usage": turns, "tool_invocations": tools,
        "source_sha256": sha(source.read_bytes()) if source.is_file() else None, "seconds": time.time() - t0,
        "allowance_before": before, "allowance_after": after,
        "allowance_change": allowance(before, after),
    })
    print("Agent final external verification:", "MATCH" if final["match"] else "NO MATCH")
    print("Saved:", destination)


def report(args):
    """Report common pipeline cost and two refinements of its identical output."""
    base = experiment_dir(args.address)
    info = read(base / "experiment.json")
    stages = {}
    for name in ("pipeline", "isolated", "agent"):
        file = base / name / "result.json"
        stages[name] = read(file) if file.is_file() else {"status": "not run"}

    def usage_of(data):
        u = data.get("total_tokens") or {}
        inp = u.get("input_tokens", 0)
        cached = u.get("cached_input_tokens", 0)
        out = u.get("output_tokens", 0)
        return {
            "input_tokens": inp,
            "cached_input_tokens": cached,
            "uncached_input_tokens": max(inp - cached, 0),
            "output_tokens": out,
            "total_tokens": inp + out,
        }

    def pct(data, window):
        return ((data.get("allowance_change") or {}).get(window) or {}).get(
            "estimated_percentage_point_change")

    common = stages["pipeline"]
    first = stages["isolated"]
    second = stages["agent"]
    handoff_hash = common.get("handoff_sha256")
    hashes = {
        "pipeline_handoff": handoff_hash,
        "isolated_start": first.get("starting_source_sha256"),
        "agent_start": second.get("starting_source_sha256"),
    }
    comparable = bool(handoff_hash and hashes["isolated_start"] == handoff_hash
                      and hashes["agent_start"] == handoff_hash)
    rows = []
    for name, run_data in (("isolated", first), ("agent", second)):
        shared = usage_of(common)
        incremental = usage_of(run_data)
        full = {key: shared[key] + incremental[key] for key in shared}
        rows.append({
            "approach": "pipeline + " + name,
            "byte_match": run_data.get("match"),
            "starting_candidate_sha256": run_data.get("starting_source_sha256"),
            "shared_pipeline_tokens": shared,
            "refinement_tokens": incremental,
            "end_to_end_tokens": full,
            "shared_pipeline_five_hour_pp": pct(common, "primary"),
            "refinement_five_hour_pp": pct(run_data, "primary"),
            "shared_pipeline_weekly_pp": pct(common, "secondary"),
            "refinement_weekly_pp": pct(run_data, "secondary"),
            "refinement_seconds": run_data.get("seconds"),
        })
    result = {
        "target": info["target"],
        "model": MODEL,
        "baseline_commit": info["baseline_commit"],
        "context_sha256": info["context_sha256"],
        "evidence_sha256": info["evidence_sha256"],
        "comparison_valid_identical_starting_candidates": comparable,
        "seed_hashes": hashes,
        "common_pipeline": common,
        "refinements": {"isolated": first, "agent": second},
        "comparisons": rows,
    }
    save(base / "comparison.json", result)
    lines = [
        "# Spore byte-match refinement comparison",
        "",
        f"Target: {info['target']['address']} ({info['target']['retail_bytes']} retail bytes)",
        "Model: " + MODEL,
        "Spore commit: " + info["baseline_commit"],
        "Identical starting C++ candidate: " + ("YES" if comparable else "NOT VERIFIED"),
        "",
        "The pcode2cpp pipeline is the COMMON first stage, not a competing arm.",
        "Both final refinements receive exactly the same pipeline output.",
        "",
        "| Metric | Pipeline + isolated Codex | Pipeline + agentic Codex |",
        "|---|---:|---:|",
    ]
    metrics = [
        ("byte_match", "Final verified byte-exact MATCH"),
        ("refinement_seconds", "Final refinement elapsed seconds"),
    ]
    for key, title in metrics:
        lines.append("| " + title + " | " + " | ".join(str(r[key]) for r in rows) + " |")
    for section, title in [
        ("shared_pipeline_tokens", "Common pipeline tokens"),
        ("refinement_tokens", "Additional Codex refinement tokens"),
        ("end_to_end_tokens", "End-to-end tokens"),
    ]:
        for key in ("total_tokens", "uncached_input_tokens", "cached_input_tokens", "output_tokens"):
            lines.append("| " + title + " (" + key + ") | " +
                         " | ".join(str(r[section][key]) for r in rows) + " |")
    for key, title in [
        ("shared_pipeline_five_hour_pp", "Common pipeline 5h allowance change (pp, approx.)"),
        ("refinement_five_hour_pp", "Extra refinement 5h allowance change (pp, approx.)"),
        ("shared_pipeline_weekly_pp", "Common pipeline weekly change (pp, approx.)"),
        ("refinement_weekly_pp", "Extra refinement weekly change (pp, approx.)"),
    ]:
        lines.append("| " + title + " | " + " | ".join(str(r[key]) for r in rows) + " |")
    lines.extend([
        "",
        "Percentages are rounded and may reset between stages; do not combine",
        "percentage-point changes across different rate-limit windows.",
        "All successful matches must be independently verified by Spore check.py.",
    ])
    (base / "comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    for row in rows:
        print(f"{row['approach']}: MATCH={row['byte_match']}, "
              f"refinement_tokens={row['refinement_tokens']['total_tokens']}, "
              f"total_tokens={row['end_to_end_tokens']['total_tokens']}, "
              f"refinement_5h_delta≈{row['refinement_five_hour_pp']}pp")
    print("Same starting candidate:", comparable)
    print("Saved:", base / "comparison.json")
    print("Saved:", base / "comparison.md")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("run", "prepare", "pipeline", "isolated", "agent", "report"))
    p.add_argument("--address", help="0x... address; optional only for prepare")
    p.add_argument("--spore", type=Path, default=Path.home() / "spore-decomp")
    p.add_argument("--min-bytes", type=int, default=768)
    p.add_argument("--max-bytes", type=int, default=1536)
    p.add_argument("--rounds", type=int, default=4)
    p.add_argument("--sweep-limit", type=int, default=64)
    p.add_argument("--workers", type=int, default=16)
    args = p.parse_args()
    if args.action in ("pipeline", "isolated", "agent", "report") and not args.address:
        p.error("--address is required for pipeline, isolated, agent and report")
    if args.rounds < 1 or args.sweep_limit < 0 or args.workers < 1:
        p.error("Invalid budgets")
    try:
        if args.action == "run":
            args.address = prepare(args)
            print("=== STAGE 1: pcode2cpp initial pipeline ===", flush=True)
            pipeline(args)
            base = experiment_dir(args.address)
            data = read(base / "pipeline/result.json")
            if not data.get("pipeline_complete") or not data.get("handoff_sha256"):
                print("Pipeline did not finish mechanical verification or produce a valid "
                      "candidate. Codex refinement will NOT run.", flush=True)
                report(args)
                return 2
            if data.get("match"):
                print("Pipeline already produced a byte-exact MATCH. Refinements unnecessary.", flush=True)
                report(args)
                return 0
            print("=== STAGE 2A: isolated Codex final refinement ===", flush=True)
            isolated(args)
            print("=== STAGE 2B: normal agentic Codex final refinement ===", flush=True)
            agent(args)
            print("=== FINAL: comparison report ===", flush=True)
            report(args)
        else:
            {"prepare": prepare, "pipeline": pipeline, "isolated": isolated,
             "agent": agent, "report": report}[args.action](args)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as e:
        print(f"spore_ab_benchmark: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
