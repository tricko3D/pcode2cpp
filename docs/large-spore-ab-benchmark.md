# Large, never-decompiled Spore function benchmark

This experiment compares three distinct approaches on one previously unimplemented
retail function. It does not delete or alter any tracked Spore implementation.

## Fair comparison controls

- Select the largest unclaimed function in the 768–1536 byte interval that
  has no implementation, no source marker, no note, no equivalent proof,
  no library implementation, and no matching-shape shortcut.
- All three runs use exactly the same clean Spore Git commit. Each gets an
  independent extracted copy, initially containing only the address marker.
  Preparation runs an external negative-control check before any model calls.
- All use GPT-6.2 Sol. They receive the same AGENTS.md instructions and
  Ghidra evidence, saved with SHA-256 checksums.
- Objective is Spore's actual VC9 byte-exact MATCH, not EQUIVALENT.
- The difference is method: (1) pcode2cpp model calls, compiler feedback
  and bounded C2Scope rewrites; (2) one isolated, tool-free inference
  with independent verification; (3) Codex free to use repository/compiler tools.
- Both exploratory arms have a nominal two-hour cap. The isolated arm has
  one model call and no iterative repair. The pipeline defaults to four
  model rounds and C2Scope sweeps bounded to 64 variants each.
  Different numbers of model/tool calls are a *measured outcome*, not held fixed.
- Model token counts and approximate 5-hour/weekly Plus allowance deltas
  are stored in each arm's result.json. Rate limits may be rounded or reset
  mid-run and other simultaneous Codex activity would contaminate the deltas.
- Check.py's verified MATCH result is the success criterion. A valid
  EQUIVALENT result is NOT a success for this comparison.

The existing scripts/run_pipeline.py, its Unicorn/angr adapters, and its
VC9 test wrapper are hard-coded to 0x00672CF0. This new harness is the
generalized *experimental* path using the same pcode2cpp Ghidra/prompt/model
components, Spore's authoritative check.py, and C2Scope. Do not describe its
output as the result of the older address-specific run_pipeline.py.

## Local WSL commands

Run from ~/pcode2cpp after updating the repository:

    git pull --ff-only
    python3 scripts/select_large_spore.py --min-bytes 768 --max-bytes 1536
    python3 -u scripts/spore_ab_benchmark.py prepare

Prepare prints the chosen 0xADDRESS. It exports the complete Ghidra
context from the local project and creates three independent Spore checkouts
under cases/spore-ab/ADDRESS. The benchmark refuses an existing experiment
directory rather than overwriting earlier measurements.

Replace ADDRESS with the printed 0x... address:

    python3 -u scripts/spore_ab_benchmark.py pipeline --address ADDRESS
    python3 -u scripts/spore_ab_benchmark.py isolated --address ADDRESS
    python3 -u scripts/spore_ab_benchmark.py agent --address ADDRESS
    python3 scripts/spore_ab_benchmark.py report --address ADDRESS

For a strict one-shot-versus-agent comparison, run the isolated arm
immediately before the agent, with no concurrent Codex sessions. Run the
pipeline first so it receives no solutions produced by the agent.
The pipeline and agent consume separate checkouts; no candidate source
is copied from one arm to another.

## Artifacts

    cases/spore-ab/ADDRESS/
      experiment.json                 chosen VA, size, source SHA, model
      context.json                    original Ghidra export
      evidence.md                     common evidence and AGENTS.md rules
      pipeline/baseline_check.json    pre-run negative control
      pipeline/logs/                  source candidates, VC9 logs, C2Scope logs
      pipeline/result.json            model tokens, checks, allowance snapshots
      isolated/baseline_check.json    pre-run negative control
      isolated/final-check.log        independent VC9/fingerprint check
      isolated/result.json            one inference's tokens and allowance
      agent/baseline_check.json       pre-run negative control
      agent/codex.jsonl               Codex's tool/event/token trace
      agent/final-check.log           independent VC9/fingerprint check
      agent/result.json               tokens, tools and allowance
      comparison.json                 combined structured record

The cases/ directory is ignored by Git. Do not commit game binaries,
raw Ghidra content, toolchains or the full agent transcript. If sharing
results, use the sanitized summary fields from comparison.json.

## Execution and safety limits

The benchmark runs on the local machine, not through GitHub. Your local
Ghidra project, Spore executable analysis image, installed Microsoft
compiler, Wine, C2Scope and authenticated Codex CLI must be available.

The agent runs with Codex's danger-full-access sandbox option because the
previous restricted run blocked Wine socket binding. That grants it broad
filesystem access. For isolation beyond separate *source* trees, use a
dedicated WSL distribution/VM. The local work/toolchain reference remains
linked to the existing Spore installation.

If Ghidra cannot export, the generated source is un-compilable, or
C2Scope does not support the function's control flow, retain the error in
the record rather than silently claiming completion. Check source
identity and the independent final check before interpreting an exact match.
