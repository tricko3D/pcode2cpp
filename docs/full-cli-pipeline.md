# One-command pipeline, initial reconstruction and compiler-guided AI fallback

The Python CLI uses the existing Ghidra export, Spore VC9 verifier, C2Scope
sweeps, Unicorn differential testing, and angr proofs. **No Jupyter is used.**
All generated code, model prompts, reports and SQLite state remain in ignored
working folders. The system never modifies Spore's tracked sources or proof
manifests.

This is **the 0x00672CF0 Spore pilot**. The initial Ghidra model interface
can process full exported context, but the VC9 wrapper, fingerprint, Unicorn,
and angr adapters are currently specific to this function. Other addresses
should not be passed to this runner until a general verification adapter exists.

## Configure models

```bash
cd ~/pcode2cpp
cp config.model-profiles.example.json config.model-profiles.json
```

Start your llama.cpp server with the model you want to run locally. Its endpoint
is configured separately from its model weights: to test Inkling 2 Small
instead of Mini, start Small on that endpoint and select `inkling-small`.
The runner does not launch the LLM server or select/install GGUF files.
Each model profile defines endpoint URL, model ID, output budget and timeout;
local inference does not require an API key.

DeepSeek's API currently uses `deepseek-flash` on
`https://api.deepseek.com/chat/completions`. The example uses this current ID,
not the old `deepseek-chat` alias. Model IDs can change: edit the profile or
verify available IDs via DeepSeek's official `/models` endpoint. Set the
credential as an environment variable:

```bash
export DEEPSEEK_API_KEY='your-key-here'
```

Remote requests **must** include `--allow-remote`. They send prompt content,
C++ source, and assembly to that service. Initial model requests can include
Ghidra's entire function context and direct callee evidence. No keys are
written to the request logs. All endpoints must use HTTPS except loopback.

## Full process, starting from Ghidra

```bash
cd ~/pcode2cpp
python -u scripts/run_pipeline.py \
  --address 0x00672cf0 \
  --models config.model-profiles.json \
  --initial-model inkling-small \
  --fallback-model inkling-small \
  --max-compiles 3000 \
  --ai-rounds 3 --ai-compiles-per-round 400 \
  --beam-width 16 --workers 16
```

This sequence performs: Ghidra context extraction from the existing Ghidra
project configured in `config.json` (or reuse with `--context path.json`),
constrained initial model reconstruction, a 32-bit Clang syntax check and
optional one-step repair, VC9+C2Scope mechanical search, then **only after**
mechanical search is exhausted, AI proposals from the best compiled/proven
candidate. It feeds the AI candidates back to VC9, C2Scope, Unicorn and angr
for each subsequent round. Exact fingerprint `MATCH` terminates the loop.

The initial reconstruction is saved under
`cases/00672cf0/full_pipeline/inkling-small/`; rerunning that profile reuses
its seed. Change `--run-dir` for fresh independent experiments.

## Continue today's 3,585-compile search with Inkling Small

This skips the initial model and Ghidra stages and resumes the existing SQLite
search with its best EQUIVALENT source. Using a cumulative 3,600 mechanical
compile limit, it invokes Inkling **only after** the existing search stalls:

```bash
python -u scripts/run_pipeline.py \
  --seed cases/00672cf0/probe_prompt_v004_run001_repair001.cpp \
  --models config.model-profiles.json \
  --fallback-model inkling-small \
  --max-compiles 3600 \
  --ai-rounds 3 --ai-patches 6 \
  --ai-compiles-per-round 400 \
  --workers 16
```

If the initial candidate is unchanged, the auto-match workdir resolves to
`cases/00672cf0/auto_match/6d533a9d9571`. Existing proofs and compilations
are reused; no previous run is reset.

## Later, try DeepSeek on the same mechanical evidence

```bash
python -u scripts/run_pipeline.py \
  --seed cases/00672cf0/probe_prompt_v004_run001_repair001.cpp \
  --models config.model-profiles.json \
  --fallback-model deepseek --allow-remote \
  --max-compiles 3600 \
  --ai-rounds 3 --ai-compiles-per-round 400
```

For a fair Inkling versus DeepSeek comparison, supply a separate `--work-dir`
for each experiment, starting from the same validated baseline; otherwise
both models share the accumulated compiler search history. AI requests/responses
are saved with the model profile and round, not replayed on resume. Expanding
`--ai-rounds` continues to a new round. Costs depend on the selected remote
provider and output token budgets.

## What the AI sees after compiler stagnation

The best proven C++ source, original and candidate VC9 assembly, the exact
assembly diff, C2Scope `rdiff` and `bdiff`, plus short previous experiment
summaries. It returns up to six independent, exact-text `find`/`replace`
source mutations. No tool calls, no inline assembly, and no direct proof claims.
Every distinct proposed source goes through the native VC9 fingerprint check.
Promising variants undergo Unicorn differential execution and angr proof.
A lower assembly difference is *not* a proof of equivalence.

Run the AI fallback without initial reconstruction or full-pipeline orchestration:

```bash
python -u scripts/ai_fallback.py \
  --seed cases/00672cf0/probe_prompt_v004_run001_repair001.cpp \
  --models config.model-profiles.json --model inkling-small \
  --max-compiles 3600 --ai-compiles-per-round 400
```

Both CLIs are fully independent of `notebooks/reconstruct.ipynb`.

## Offline tests

```bash
python -m unittest tests.test_model_client tests.test_ai_fallback tests.test_run_pipeline -v
python -m unittest tests.test_auto_match -v
```

Tests mock the model, Spore toolchain and compiler. Real byte matching and
Ghidra/VC9 interoperability must be checked on your WSL machine.
