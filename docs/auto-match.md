# Automated VC9 matching (Spore pilot)

`auto_match.py` automates multi-generation C2Scope rewrites against retail Spore
function `0x00672cf0`. This is an opt-in Spore-specific research pilot, not
part of the general Ghidra-to-C++ translator. It **does not use an LLM** after
the seed, edit upstream `match/` slices, claim functions, or record proof bundles.

The search integrates:

- `rwsweep.py` for measured, meaning-preserving (according to its rewrite
  rules) source mutations and VC9 `rdiff`/`bdiff` scoring. Compiled candidates
  are checked independently rather than assumed equivalent.
- A field-dependency mutation that reads a pointer-valued field written earlier
  in the function. For the pilot, `param_1[2] = (int)(param_1 + 0x15)` can become
  `param_1[2] = (int)((unsigned int)param_1[4] + 0x40u)` after the earlier
  `param_1[4]` initialization. **This can change behavior when memory aliases**;
  it is a search hypothesis, never automatically labelled equivalent.
- Spore's existing VC9 fingerprint backend, Unicorn differential test, and
  `prove_spore_candidate.py` angr worker. No proof logic is reinvented.
- SQLite candidate records under an ignored `cases/` work directory, machine-code
  deduplication, and a source archive that retains identical-code variants
  for field-dependency lookahead. By default, those duplicates are not given
  another full C2Scope sweep; the tradeoff can be changed with
  `--machine-alternatives`.

## Run

The seed can be the original, unmodified Inkling probe, or a **prepared VC9
translation unit** containing `InklingCandidate_s00672cf0::FUN_00672cf0`.
For the proven `v0037` from the original experiment:

```bash
cd ~/pcode2cpp
git pull --ff-only
python -u scripts/auto_match.py \
  --seed ~/spore-decomp/work/pcode2cpp_checks/v0037.cpp \
  --beam-width 16 --workers 16 \
  --max-compiles 2000 --max-generations 6
```

Starting from the earlier unverified source enables the search to rediscover
field dependencies and multi-generation rewrites rather than assume `v0037`.

```bash
python -u scripts/auto_match.py \
  --seed cases/00672cf0/probe_prompt_v004_run001_repair001.cpp
```

The same command resumes its matching SQLite database and skips expanded
parents. `--work-dir` chooses a separate, dedicated experiment directory.
Changing the seed, toolchain paths, mutation families or compiler flags in an
existing work directory is refused to prevent mixing different experiments.
Increasing `--max-compiles` or `--max-generations` on a resumed run is allowed.

C2Scope is launched with the 15.00 backend and `/O2 /MD /Gy /EHsc /TP`. Its
parallel compilation uses `--workers` and `C2TRACE_REMOTE=0`; `VIRTUAL_ENV`
is cleared so `uv` selects C2Scope's own environment. The default worker count
is `os.cpu_count()`; explicitly set it if your VC9 tracing setup has a lower
capacity. The compilation budget is **an estimate**, counting reported
C2Scope sweeps, planned combinations and snapshots, not an exact counter of
all internal tool invocations.

## State and search policy

The work directory contains:

- `search.sqlite3`: candidate provenance, parent, generation, source hash,
  C2Scope scores, compiled machine hash, verification result, expansion status
  and sweep counts.
- `sources/<hash>.cpp`: immutable, deduplicated VC9-ready source variants.
- `logs/`: C2Scope stdout, retail/candidate assembly, VC9 snapshots, Unicorn
  and angr logs.
- `summary.json`: compile estimate, result counts and best proven candidate.

Each parent generates C2Scope variants plus derived-field expressions. The
controller ranks `rdiff`, then `bdiff`, but reserves beam capacity for the
new source family before it has a measured C2Scope score. It keeps at most
`--machine-alternatives` C++ representations per machine-code class for
follow-up exploration. C2Scope output is copied into the search store before
another sweep can clear its own work directory.

Selected novel code is compiled with the Spore VC9 backend. The highest-ranked
new candidates get Unicorn and then angr checks (defaults:
`--evaluate-top 24`, `--unicorn-top 8`, `--formal-top 4` per generation).
Candidates not independently proven remain explicitly unverified. A
`REFUTED` intermediate may still be expanded, since a later transformation
can eliminate its counterexample; it must **never** replace the best proved
candidate. `UNKNOWN` is not accepted as proof. An exact fingerprint is marked
`MATCH` only when the expected external callee symbol is present; linkage is
still synthetic and its target address is not independently resolved.

The search stops on `MATCH`, exhaustion, the generation cap or the estimated
compile budget. A successful return without `MATCH` means a proven-equivalent
candidate exists, **not** that a byte match was obtained. Inspect
`summary.json` to distinguish these outcomes. Proof results are only held in
the experiment's database; Spore's own proof records are untouched.

## Current boundaries

This is a runnable automation of the Spore pilot, **not** a universal automatic
decompiler. The C2Scope rewrite catalog and this first field-dependency
operator are not exhaustive, the search may stall, and some candidates can
be refuted by adversarial pointer aliases. There is no learned search policy
or automated new-rewrite synthesis yet, and Inkling is deliberately not part
of this search loop. The tool has unit tests that mock the external compilers
and proofs, but a full live VC9/C2Scope/Spore search must be exercised in the
user's WSL environment.

Offline tests:

```bash
python -m unittest tests.test_auto_match -v
```


## Search scheduling after the first live run

The initial 2,000-compile experiment reached a 57-byte formally equivalent
candidate, but spent the second-generation budget sweeping several equivalent
machine-code candidates before compiling cross-family rewrites. The controller
now prioritizes field-dependency rewrites derived from *each newly discovered
C2Scope variant*, not just from already-expanded parents. It evaluates pending
candidates between parent sweeps, uses at most three sweeps per generation,
reserves compile budget for candidate evaluation, and defaults to 160 variants
per sweep rather than 500. Exact-machine duplicates are not expensive sweep
parents by default (`--machine-alternatives 1`), but their C++ can still
contribute field-dependency expressions.

**Existing SQLite state is reused.** On startup the search backfills
field-dependency combinations from previously compiled variants, including
variants whose C2Scope sweeps were already marked complete. These new
combinations are compiled before additional sweeps. Increasing the total
budget does not reset past compile costs or overwrite proofs:

```bash
cd ~/pcode2cpp
git pull --ff-only
python -m unittest tests.test_auto_match -v

python -u scripts/auto_match.py \
  --seed cases/00672cf0/probe_prompt_v004_run001_repair001.cpp \
  --beam-width 16 --workers 16 \
  --max-compiles 3000 --max-generations 6
```

This resumes `cases/00672cf0/auto_match/6d533a9d9571`, including
the 2,000 estimated compiles already spent. The additional 1,000 compiles
are a search budget, not a promise of a byte match. The generated provenance,
VC9 outputs and proof records remain local, ignored research artifacts.

The mechanical mutation catalog is still incomplete, and the current
regression tests mock compiler/prover backends rather than reproducing a full
WSL matching run. A successful empirical Unicorn test alone never upgrades
a candidate to EQUIVALENT.
