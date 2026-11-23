# C2Scope feedback experiment: Spore 0x00672CF0

This is an opt-in experiment, separate from the initial single-request Ghidra translator. It uses the existing compiler-repaired candidate, not Spore's tracked source. It does not alter Spore manifests, record proofs, or retransmit the full Ghidra prompt.

Requires a running local llama.cpp server, a configured Spore checkout with VC9 and the retail analysis image, Clang, and an installed `~/c2scope` with the 15.00 backend configured.

From `~/pcode2cpp`, inspect the real C2Scope trace without inference:

```bash
python -u scripts/c2scope_feedback.py --dry-run
```

Then, with the local model running, start the feedback experiment:

```bash
python -u scripts/c2scope_feedback.py --rounds 3
```

Each invocation creates a unique directory under `cases/00672cf0/c2scope_runs/runNNN/`. Its files include original and VC9 assembly, C2Scope `icount` reports, register-allocation and scheduling logs, the constrained JSON model request and response, and per-candidate compiler, Unicorn and formal proof logs.

C2Scope is invoked with the 15.00 backend and `/O2 /MD /Gy /EHsc /TP`. Its compile runs locally with `C2TRACE_REMOTE=0`. Instruction-count analysis is mandatory and stops inference if unavailable; register and scheduling findings are supplemental.

The runner preserves the original candidate and makes one local model request per round, with only the current body, assembly and C2Scope diagnostics. Every new candidate must pass Clang and VC9. Non-byte-matches must pass Unicorn differential testing with at least 200 valid runs before continuing, and the existing Spore prover is called with that particular candidate object. The loop stops immediately on a fingerprint match. Change `--rounds`, `--max-tokens`, `--inputs`, and `--proof-timeout` as needed.

**Interpretation:** Clang and VC9 compilation is not equivalence. Unicorn PASS is empirical evidence, not formal proof. Angr's previous `call#0 esp` refutation is not suppressed. The reported instruction-shape similarity is a heuristic only. A fingerprint PASS is exact under Spore's relocation masking rules, but the synthetic callee declaration's actual link target of `0x00672750` is assumed, not independently verified.

Spore's tracked sources remain unchanged. Generated wrappers go into its ignored `work/pcode2cpp_checks/`, and generated reports and retail disassembly remain under the locally ignored `cases/` tree.

## Recover a C2Scope trace after Inkling exhausts reasoning

If the model produced only a long `[Reasoning]` transcript and ended with `finish_reason=length`, no new C++ candidate was accepted. The completed C2Scope instruction-count, register, and scheduler trace can be reused:

```bash
cd ~/pcode2cpp
python -u scripts/c2scope_feedback.py --rounds 3 \
  --resume-feedback cases/00672cf0/c2scope_runs/run002/probe_prompt_v004_run001_repair001_c2scope_001.feedback.json
```

The new run gets its own `runNNN/` folder, builds a fresh snapshot of the current candidate, and takes C2Scope data from `run002` only for round 1. Subsequent rounds gather new compiler traces.

This experiment now defaults to `chat_template_kwargs.reasoning_effort="minimal"`, output capped at the smaller of `4096` or the existing LLM configuration's `max_tokens`, and a 10,000-character maximum for reasoning before the first JSON chunk. Inkling 2 Mini reads `reasoning_effort` rather than `enable_thinking`; `minimal` reduces thinking but does not promise to turn it off completely. Customize with `--reasoning-effort none|low|medium|high|xhigh`, `--reasoning-limit-chars N`, and `--max-tokens N`. Full reasoning is written to the transcript while stdout shows only the first 400 characters. A repetition or truncation aborts without accepting a partial function.
