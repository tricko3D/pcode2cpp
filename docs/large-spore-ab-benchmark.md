# Spore: shared pcode2cpp pipeline, then two Codex refinement approaches

This benchmark is a TWO-WAY comparison of how to improve the output of the
SAME pcode2cpp pipeline. Isolated Codex is the last step of the pipeline,
not a separate reconstruction from Ghidra. Agentic Codex is the alternative
last step, starting from precisely the same pipeline candidate.

## Benchmark design

1. Select one genuinely unimplemented, unclaimed 768–1536-byte function
   using Spore's own task.py. Exclude existing definitions, notes,
   equivalents, library functions and matching-shape shortcuts.
2. Export its Ghidra analysis once, preserve it, and archive the exact same
   upstream Spore Git commit into three independent working directories.
   All three start with no function implementation. Before any inference,
   check.py verifies the function is not already a match.
3. Run the experimental generalized pcode2cpp pipeline using GPT-6.2 Sol,
   Ghidra decompiled C, full High P-code, x86 assembly, VC9 compiler feedback
   and bounded C2Scope rewriting. It saves the best compiler-valid source
   found at pipeline/handoff.cpp and a SHA-256 identity.
4. FINAL OPTION A, isolated Codex: install that exact handoff candidate,
   send the existing source, Ghidra evidence, repository AGENTS.md and last
   VC9 feedback to Codex with no model tools, and allow ONE source refinement.
   Independently compile and fingerprint the result.
5. FINAL OPTION B, normal Codex agent: install the IDENTICAL handoff,
   supply the same Ghidra evidence and instructions, allow Codex to use
   repository/compiler tools and iterate. Independently verify the result.
6. Compare pipeline + isolated versus pipeline + agentic, using the common
   pipeline cost once, plus each final-refinement cost separately.

**Success means BYTE-EXACT MATCH from Spore's VC9 fingerprint check.**
Equivalent is not a match. The report rejects an apples-to-apples claim
unless both refinement arms' starting source SHA-256 values equal the
pipeline handoff SHA-256.

All runs use the exact model gpt-6.2-sol. The pipeline's reconstruction and
C2Scope budget is not duplicated. Model-call counts, allowed tools and source
rewrite strategies differ deliberately, and are experimental variables.
The isolated option is only one model call, while the agent is iterative.
The experiment does not infer identical wall time or token budget from this.

The existing scripts/run_pipeline.py and its Unicorn/angr verification
adapters currently work only for 0x00672CF0. The generalized benchmark
runner reuses pcode2cpp's Ghidra/prompt/model implementation and Spore's
authoritative check.py plus C2Scope. It is an experimental adaptation,
not the unchanged 0x00672CF0 verifier.

## Start from scratch on WSL

Run this single command from a fresh pcode2cpp checkout:

    cd ~/pcode2cpp
    git pull --ff-only
    python3 -m unittest discover -s tests -p 'test_spore_ab_benchmark.py' -v
    python3 -u scripts/spore_ab_benchmark.py run

The `run` action automatically picks an eligible, never-decompiled large
function; exports its Ghidra evidence; runs pcode2cpp; saves its final C++
candidate; then compares isolated versus agentic Codex improvement of that
same candidate; finally saves the token and usage comparison. The selector
reports its progress so a large source scan is not silent.

If an environment failure interrupts the run, the experiment retains data
for completed stages; individual `pipeline`, `isolated`, `agent` and
`report` actions remain available for inspection/recovery. If the
pipeline fails to yield a valid compilable candidate, the later stages
do not run and the report records that failure rather than fabricating
a result.

Run sequentially and without another Codex session to minimize allowance
measurement contamination. The actual Codex rate-limit percentages are
rounded and may not update on each model request.

## Output

Under cases/spore-ab/ADDRESS/:

- experiment.json: function identity, retail size, baseline commit and hashes
- context.json and evidence.md: shared Ghidra evidence and instructions
- pipeline/logs/: reconstruction candidates, compiler logs, C2Scope sweeps
- pipeline/handoff.cpp: the EXACT source both refinements must begin with
- pipeline/result.json: shared pipeline model tokens and Plus-allowance readings
- isolated/result.json and isolated/final-check.log: final inference and verifier
- agent/result.json, agent/codex.jsonl, agent/final-check.log: final agent costs,
  tool activity, compiler verification
- comparison.json and comparison.md: **two** end-to-end approaches with shared
  pipeline cost, marginal refinement cost, cached and uncached tokens,
  5-hour and weekly rounded allowance readings and matching-source checks

The cases/ directory is gitignored; do not commit the retail binary,
analysis image, Ghidra JSON or private Codex session transcript.

Codex agent mode currently uses --sandbox danger-full-access to permit
Wine to bind sockets, because restricted sandboxing blocked it in the
previous experiment. Work with an expendable WSL distro or VM if stronger
host isolation is needed. The separate working copies preserve source
results but do not constitute OS-level sandboxing.
