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
    checkout = base / arm / "spore"
    source = checkout / info["target_source"]
    expected = f"// @ {info['target']['address']}\\n// No implementation yet.\\n"
    if source.read_text(encoding="utf-8") != expected:
        raise RuntimeError(f"Refinement source is not pristine: {source}")
    source.write_bytes(contents)
    feedback = (previous.get("handoff_verification") or {}).get("feedback", "")
    prompt = (
        f"Target: {info['target']['address']} ({info['target']['retail_bytes']} retail bytes).\\n"
        "The target C++ file contains the candidate produced by pcode2cpp. "
        "IMPROVE it toward a VC9 byte-exact MATCH, not equivalence. "
        "Preserve observable semantics, ABI and calls. "
        "Do not inspect history or retrieve an existing solution.\\n\\n"
        "Final pipeline compiler and fingerprint feedback:\\n" + feedback
    )
    scratch = checkout / "work/scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    (scratch / "refine_prompt.md").write_text(prompt, encoding="utf-8")
    return digest, prompt


def verify(checkout, address, path):
    p = command([str(checkout / ".venv/bin/python"),
                 "tools/contrib/check.py", address, "--no-quick"],
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
    asm = folder / "original.s"
    retail_assembly(checkout, address, asm)
    cmd = [
        "uv", "run", "tools/rwsweep.py", str(source),
        "--func", symbol, "--asm-vs", str(asm),
        "--families", A.DEFAULT_FAMILIES, "--jobs", str(workers),
        "--limit", str(limit), "--max-combo", "2", "--verify", "8",
        "--c2", "15.00", "--", *flags
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
            print(f"Pipeline model round {n + 1}: {'MATCH' if result['match'] else 'not matched'}", flush=True)
            if result["match"]:
                matched = True
                break
            feedback = result["feedback"]
            if result["symbol"] and result["compiler_flags"] and args.sweep_limit > 0:
                try:
                    folder = logs / f"c2scope_{n:02d}"
                    ranked, count = mechanical(
                        checkout, address, source, result["symbol"], folder,
                        args.workers, args.sweep_limit, result["compiler_flags"])
                    trials.append({"round": n, "kind": "c2scope", "measured": count,
                                   "ranked_scores": [[name, rd, bd] for name, rd, bd, _ in ranked]})
                    for i, (name, rd, bd, path) in enumerate(ranked):
                        if not path.is_file():
                            continue
                        source.write_bytes(path.read_bytes())
                        v = verify(checkout, address, folder / f"candidate_{i}.log")
                        trials.append({"round": n, "kind": "c2scope_check",
                                       "variant": name, "rdiff": rd, "bdiff": bd, **v})
                        if v["match"]:
                            matched = True
                            break
                    if matched:
                        break
                    source.write_text(cpp.rstrip() + "\n")
                    feedback += "\nC2Scope measured:\n" + json.dumps(
                        [{"name": x[0], "rdiff": x[1], "bdiff": x[2]} for x in ranked])
                except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
                    trials.append({"round": n, "kind": "c2scope_error", "error": str(e)})
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
        failure = str(e)
    after = snapshot_limits()
    totals = {
        key: sum((u.get("usage") or {}).get(key, 0) for u in tokens)
        for key in ("input_tokens", "cached_input_tokens", "output_tokens")
    }
    save(destination, {
        "arm": "pipeline", "model": MODEL, "match": matched, "error": failure,
        "total_tokens": totals, "model_calls": tokens, "attempts": trials,
        "source_sha256": sha(source.read_bytes()) if source.is_file() else None, "seconds": time.time() - t0,
        "allowance_before": before, "allowance_after": after,
        "allowance_change": allowance(before, after),
    })
    print("Saved:", destination)


def isolated(args):
    """One independent, inference-only Codex response, with no repair/search calls."""
    base, info, checkout, source = load_arm(args.address, "isolated")
    destination = base / "isolated/result.json"
    if destination.exists():
        raise RuntimeError("Isolated run already recorded; refusing to overwrite")
    profile = load_profile(ROOT / "config.model-profiles.example.json", "codex-plus")
    profile["model"] = MODEL
    evidence = (base / "evidence.md").read_text()
    address = info["target"]["address"]
    before = snapshot_limits()
    t0 = time.time()
    failure, usage = None, {}
    try:
        response, usage = chat_json(profile, [
            {"role": "system", "content":
             "You reconstruct native VC9 C++ for a never-decompiled Spore function. "
             "No compiler, shell, repository, or web tools. Return a JSON object "
             "with the key body containing a complete compilable .cpp file."},
            {"role": "user", "content": evidence +
             "\n\nReturn the complete C++ translation unit. Include a single marker "
             "line // @ " + address + " immediately before the target function. "
             "No inline assembly, no placeholders. The goal is BYTE-EXACT MATCH."},
        ])
        cpp = response.get("body")
        if not isinstance(cpp, str) or not cpp.strip():
            raise RuntimeError("Isolated Codex response has no C++ source")
        if "// @ " + address not in cpp:
            raise RuntimeError("Isolated candidate missing required address marker")
        if re.search(r"(?im)\b(?:__asm|_asm|asm)\b|__declspec\s*\(\s*naked\s*\)", cpp):
            raise RuntimeError("Isolated candidate uses forbidden assembly")
        source.write_text(cpp.rstrip() + "\n")
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as e:
        failure = str(e)
    # Verification is outside the model. No model follow-ups for compiler errors.
    verification = verify(checkout, address, base / "isolated/final-check.log")
    after = snapshot_limits()
    save(destination, {
        "arm": "isolated", "model": MODEL, "match": verification["match"],
        "verification": verification, "error": failure,
        "total_tokens": (usage.get("usage") or {}),
        "model_calls": [usage] if usage else [],
        "source_sha256": sha(source.read_bytes()) if source.is_file() else None,
        "seconds": time.time() - t0,
        "allowance_before": before, "allowance_after": after,
        "allowance_change": allowance(before, after),
    })
    print("Isolated final verification:", "MATCH" if verification["match"] else "NO MATCH")
    print("Saved:", destination)


def agent(args):
    base, info, checkout, source = load_arm(args.address, "agent")
    destination = base / "agent/result.json"
    if destination.exists():
        raise RuntimeError("Agent already recorded; refusing to overwrite")
    address = info["target"]["address"]
    prompt = (
        "Read AGENTS.md and work/scratch/evidence.md. "
        "This is a Spore byte-matching experiment for " + address + ". "
        "Implement the completely missing function in " + info["target_source"] + ". "
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
        "total_tokens": turns[-1] if turns else {},
        "all_turn_usage": turns, "tool_invocations": tools,
        "source_sha256": sha(source.read_bytes()) if source.is_file() else None, "seconds": time.time() - t0,
        "allowance_before": before, "allowance_after": after,
        "allowance_change": allowance(before, after),
    })
    print("Agent final external verification:", "MATCH" if final["match"] else "NO MATCH")
    print("Saved:", destination)


def report(args):
    base = experiment_dir(args.address)
    info = read(base / "experiment.json")
    comparison = {
        "target": info["target"], "model": MODEL,
        "baseline_commit": info["baseline_commit"],
        "context_sha256": info["context_sha256"],
        "evidence_sha256": info["evidence_sha256"],
        "arms": {},
    }
    for arm in ("pipeline", "isolated", "agent"):
        file = base / arm / "result.json"
        comparison["arms"][arm] = read(file) if file.is_file() else {"status": "not run"}
    scorecard = {}
    for arm, value in comparison["arms"].items():
        usage = value.get("total_tokens") or {}
        inp = usage.get("input_tokens", 0)
        cached = usage.get("cached_input_tokens", 0)
        out = usage.get("output_tokens", 0)
        rate = value.get("allowance_change") or {}
        scorecard[arm] = {
            "verified_byte_match": value.get("match"),
            "model": value.get("model"),
            "input_tokens": inp,
            "cached_input_tokens": cached,
            "uncached_input_tokens": max(0, inp - cached),
            "output_tokens": out,
            "total_tokens": inp + out,
            "model_calls_or_turns": (len(value.get("model_calls") or [])
                                    if arm != "agent" else len(value.get("all_turn_usage") or [])),
            "tools_invoked": value.get("tool_invocations") if arm == "agent" else 0,
            "compiler_checks": (sum(x.get("kind") in ("model", "c2scope_check")
                                    for x in value.get("attempts", []))
                                if arm == "pipeline" else (1 if value.get("verification") else 0)),
            "c2scope_measured": (sum(x.get("measured", 0) for x in value.get("attempts", [])
                                    if x.get("kind") == "c2scope") if arm == "pipeline" else 0),
            "elapsed_seconds": value.get("seconds"),
            "five_hour_allowance_delta_pp_approx":
                (rate.get("primary") or {}).get("estimated_percentage_point_change"),
            "weekly_allowance_delta_pp_approx":
                (rate.get("secondary") or {}).get("estimated_percentage_point_change"),
        }
    comparison["scorecard"] = scorecard
    save(base / "comparison.json", comparison)
    lines = [
        "# Spore byte-match A/B comparison",
        "",
        "Target: " + info["target"]["address"] + " (" + str(info["target"]["retail_bytes"]) + " bytes)",
        "Model: " + MODEL,
        "Spore commit: " + info["baseline_commit"],
        "",
        "| Metric | Pipeline | Isolated | Agentic |",
        "|---|---:|---:|---:|",
    ]
    metrics = [
        ("verified_byte_match", "Byte-exact MATCH"),
        ("total_tokens", "Total tokens"),
        ("uncached_input_tokens", "Uncached input"),
        ("cached_input_tokens", "Cached input"),
        ("output_tokens", "Output tokens"),
        ("compiler_checks", "Direct VC9 checks"),
        ("c2scope_measured", "C2Scope variants measured"),
        ("tools_invoked", "Agent tool invocations"),
        ("elapsed_seconds", "Elapsed seconds"),
        ("five_hour_allowance_delta_pp_approx", "5h allowance delta (pp, approximate)"),
        ("weekly_allowance_delta_pp_approx", "Weekly allowance delta (pp, approximate)"),
    ]
    for key, label in metrics:
        lines.append("| " + label + " | " +
            " | ".join(str(scorecard[arm][key]) for arm in ("pipeline", "isolated", "agent")) + " |")
    lines.extend(["", "Rate-limit readings are rounded and may be stale or affected by other Codex sessions.",
                  "All success results must be backed by the real Spore check.py MATCH output."])
    (base / "comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    for arm, value in comparison["arms"].items():
        usage = value.get("total_tokens") or {}
        rate = value.get("allowance_change") or {}
        first = (rate.get("primary") or {}).get("estimated_percentage_point_change")
        second = (rate.get("secondary") or {}).get("estimated_percentage_point_change")
        print(f"{arm}: MATCH={value.get('match')}, tokens={usage}, "
              f"5h approx delta={first}pp, weekly approx delta={second}pp")
    print("Saved:", base / "comparison.json")
    print("Saved:", base / "comparison.md")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("prepare", "pipeline", "isolated", "agent", "report"))
    p.add_argument("--address", help="0x... address; optional only for prepare")
    p.add_argument("--spore", type=Path, default=Path.home() / "spore-decomp")
    p.add_argument("--min-bytes", type=int, default=768)
    p.add_argument("--max-bytes", type=int, default=1536)
    p.add_argument("--rounds", type=int, default=4)
    p.add_argument("--sweep-limit", type=int, default=64)
    p.add_argument("--workers", type=int, default=16)
    args = p.parse_args()
    if args.action != "prepare" and not args.address:
        p.error("--address is required for pipeline, isolated, agent and report")
    if args.rounds < 1 or args.sweep_limit < 0 or args.workers < 1:
        p.error("Invalid budgets")
    try:
        {"prepare": prepare, "pipeline": pipeline, "isolated": isolated, "agent": agent,
         "report": report}[args.action](args)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as e:
        print(f"spore_ab_benchmark: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
