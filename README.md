# pcode2cpp

**A local, non-agentic Ghidra High P-code → C++ translator.**

pcode2cpp takes the analysis Ghidra has already performed on a native binary and sends the *complete extracted function context* to a locally running LLM. The model returns one C++ implementation. No cloud API, no tool calling, no automated correction loop, no training and no dependency on a particular game.

The initial research setup uses **Inkling 2 Mini through llama.cpp** and **Spore (2008)** as a test program. The translator itself is model- and project-independent. **Equivalence is not assumed from an LLM output:** an optional verifier can establish a byte match or a supported behavioral proof.

## Flow

```text
Existing Ghidra project (optional imported PDB/type information)
           |
           v
export_function.py -> cases/<address>/context.json
           |
           v
reconstruct.ipynb -> explicit system instruction + all context JSON
           |
           v
local llama.cpp /v1/chat/completions (one request, no tools)
           |
           v
cases/<address>/candidate.cpp
           |
           v
optional external project verifier (separate, manual step)
```

## What the Ghidra exporter includes

For the **selected function entry address**, it writes a structured JSON record containing: decompiled C; every High P-code operation with SSA varnode information and block index; basic-block successors; x86 instructions and instruction bytes; return type, parameters, locals, inferred high variables and their types; referenced struct/class layouts and enum values; referenced globals; direct call **site and target addresses**, callee signatures and calling conventions; and explicitly unresolved indirect calls.

Symbol/type sources are preserved where Ghidra exposes them. **`IMPORTED` does not necessarily mean a particular PDB, nor guarantee that a type belongs to the retail build.** The PDB must have been imported into the Ghidra project beforehand. Unresolved call targets are recorded as `null`, never guessed.

High P-code is Ghidra's SSA-like, optimized intermediate representation, not a dump of original source-level syntax. Both its C pseudocode and the original assembly accompany it so the model can reason about semantic distinctions that were lost or simplified.

## Setup (Linux / WSL)

Python 3.10+ and an **existing Ghidra project containing an imported binary** are required. If the target address has no function yet, the notebook runs full Ghidra auto-analysis and saves the project before exporting; analysis is not repeated when the target function already exists. Install `pyghidra` in the Python environment that launches the exporter and point `GHIDRA_INSTALL_DIR` at the installed Ghidra directory when needed. The repository does not install Ghidra itself.

```bash
# From the pcode2cpp repository root
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install pyghidra
cp config.example.json config.json
```

Edit `config.json` for the analyzed Ghidra project, program file, local llama.cpp URL and optional external Spore checkout. `config.json` is ignored by Git.

**Existing Ghidra project integration (Linux/WSL and Windows):** `ghidra.project_path` is the parent directory where PyGhidra was pointed when the project was created. Both standard Ghidra projects (`<parent>/<name>.gpr`) and PyGhidra's nested layout (`<parent>/<name>/<name>.gpr`) are supported. `ghidra.project_name` is the project filename without `.gpr`; `ghidra.project_program` is the imported program name inside the Ghidra project (at its root). The legacy `ghidra.program` setting can still supply the program name, but the binary does not need to exist on disk for an existing project.

For the **existing WSL Spore retail project** (if originally created with `tools/ghidra/run.sh`), the `ghidra` section is approximately:

```json
{
  "ghidra": {
    "project_path": "/home/patrick/spore-decomp/work/ghidra",
    "project_name": "spore",
    "project_program": "SporeApp.analysis.bin",
    "install_dir": null,
    "analyze_if_missing": true,
    "timeout_seconds": 7200
  }
}
```

Set `install_dir` to the **Linux** Ghidra installation if PyGhidra cannot locate it automatically. Retain `llm` and `spore` in `config.json`. The notebook can run entirely in WSL using the existing local llama.cpp server. The exporter uses PyGhidra's `open_project` and `program_context`, opens only an already-imported program, and does **not** create projects or reimport binaries. When the requested function entry is not defined, it automatically runs a full Ghidra analysis and saves the existing project. The default analysis timeout is 7,200 seconds; `analyze_if_missing: false` prevents automatic analysis. It refuses addresses outside executable memory or inside an existing function. If full analysis still cannot identify the function, it reports that explicitly instead of inventing function boundaries.

Spore development PDB data imported into a **Windows** Ghidra project does not automatically appear in the retail Ghidra project in WSL. To use that separate development program, copy the associated `.gpr` and `.rep` project directory into the WSL filesystem and point the same configuration keys at it. Windows files can be accessed at `/mnt/c/...`, but Ghidra project databases are best kept on the native Linux filesystem. Development-build addresses and symbols must not be assumed to correspond to the retail build. The first end-to-end export should be verified on your machine.

**Run Inkling separately**, using the existing llama.cpp server with enough context for the entire function record and the requested output length. An example server endpoint is `http://127.0.0.1:8080/v1/chat/completions`. The server is *not* started by pcode2cpp. No OpenRouter/API key is used.

```bash
jupyter lab
```

Open `notebooks/reconstruct.ipynb`. Its **first code cell is self-contained** (including imports, configuration, selected `ADDRESS`, Ghidra preparation and JSON export), so running it after a kernel restart does not require extra setup cells. The remaining cells handle:

1. Inspect signatures, types, resolved calls and pseudocode.
2. Display the **full, untruncated prompt and context** that will be sent.
3. Send **one local inference request** and save the response as C++.
4. Optionally verify an already-integrated translation unit in an external project.

The notebook defaults to the known `0x00672CF0` Spore example. Change `ADDRESS` to any valid entry in the analyzed binary. Generated contexts and C++ live in untracked `cases/<address>/` directories, and inferred secrets/binary artifacts are not committed.

The exporter can also be called from ordinary Python:

```python
import json
from pcode2cpp.ghidra import export_function
from pcode2cpp.translate import translate

config = json.load(open("config.json"))
context = export_function(0x00672CF0, "cases/00672cf0/context.json", config["ghidra"])
cpp, metadata = translate(context, config["llm"])
print(cpp)
```

The Ghidra exporter directly opens an existing project and program with the PyGhidra API. It does **not** create projects, import binaries or install PDB data. When a function is missing, it can analyze and save that existing project; it never guesses a function definition.

## Standalone compact prompt generator

The full Ghidra JSON remains the canonical, unmodified export. To build a **readable, model-friendly Markdown prompt** from an already exported function, without launching Ghidra or calling an LLM:

```bash
python scripts/build_prompt.py cases/00672cf0/context.json
# Or use a function JSON from the bulk dataset:
python scripts/build_prompt.py data/retail-contexts/00672cf0.json
```

The script includes the current `prompts/reconstruct.txt` system instruction, decompiled C, original assembly, compact SSA High P-code and control flow, signatures, calls, globals, and useful referenced type layouts. Redundant JSON wrappers, machine-byte strings, and low-value type metadata are omitted. Very large type layouts are bounded, with omissions labeled. It writes `cases/00672cf0/prompt_v001.md`, then `prompt_v002.md` on the next run, preserving prior versions. Use `--system-prompt` to select a different instruction file and `--output-dir` to change the destination.

**This is a prompt generator only.** It does not make inference requests, rewrite the notebook, or change `translate.py`, which still sends full JSON unless deliberately changed later.

## Optional verification integration

The core only handles Ghidra context → local C++. A small standard `VerificationBackend` interface in `pcode2cpp/verification.py` accepts a function address and a prepared source-file path, returning one of:

| Verdict | Meaning |
|---|---|
| `MATCH` | Byte-identical after the checker's relocation rules |
| `EQUIVALENT` | Accepted behavioral proof from a supported verifier |
| `REFUTED` | Behavioral counterexample demonstrated |
| `UNKNOWN` | Proof not established (not evidence of incorrectness) |
| `COMPILE_FAILED` | Candidate did not compile |
| `ERROR` | Integration or tool error |

`integrations/spore_decomp.py` is an optional thin adapter to [NoahBPeterson/spore-decomp](https://github.com/NoahBPeterson/spore-decomp): `check.py --dry-run --no-quick` first, followed by `prove.py --json` on nonmatches. It **does not import SAD**, implement its own equivalence rules, or write anything into Spore sources.

**Manual preparation is necessary**: generated C++ is a *function implementation*, not necessarily a standalone compilable Spore object. Fit it into the correct translation unit, preserve its `// @ 0xADDRESS` marker and existing dependencies, and use a separate Spore checkout/worktree. Set `SPORE_SOURCE` in the notebook to that prepared `.cpp` file. The adapter refuses source paths outside the configured checkout and does not copy source files. The Spore checker may write temporary build outputs under the configured checkout's `work/` directory.

```python
from pathlib import Path
from integrations.spore_decomp import SporeDecompBackend

backend = SporeDecompBackend(Path("/path/to/separate/spore-decomp"))
result = backend.verify(0x00672CF0, Path("/path/to/separate/spore-decomp/match/slices/.../....cpp"))
print(result.verdict, result.details)
```

A new verifier for another binary/game can implement the same two-argument `verify(address, source)` protocol. Verification is optional, and **compiling is not the same as proving equivalence**.

## Design boundaries

- **Standalone:** the translator depends only on Ghidra's JSON output and a local OpenAI-compatible llama.cpp endpoint. Only the optional Spore adapter knows anything about Spore.
- **Non-agentic:** one request produces one response; no model tool calls, retries, code execution, or autonomous editing.
- **Transparent:** all context fields are sent; nothing is silently dropped or shortened. If the model context window is insufficient, increase it at the inference server or use a smaller function. If the output is incomplete, the source must not be treated as verified.
- **Research-first:** reconstruct semantically equivalent C++, independently establish a `MATCH` or `EQUIVALENT` verdict. Only after **100 independently verified functions** would an optional c2scope research stage attempt 1:1 byte matching. c2scope is not part of the initial tool.
- **Legality:** only analyze software and debugging data you are authorized to use. Retail code, PDBs, extracted data and generated binary-derived contexts belong in untracked local directories; do not publish them from this repository.

## Tests

```bash
python -m unittest discover -s tests -v
```

Unit tests mock Ghidra and local HTTP inference, and verify that full context survives serialization, only a single tool-free request is made, and the optional Spore adapter is read-only. **They do not prove compatibility with your installed Ghidra project, Inkling checkpoint, or Spore toolchain.** That requires end-to-end testing on your machine.

## Project layout

```text
pcode2cpp/
├── README.md
├── LICENSE
├── .gitignore
├── pyproject.toml
├── requirements.txt
├── config.example.json
├── notebooks/reconstruct.ipynb
├── ghidra_scripts/export_function.py
├── prompts/reconstruct.txt
├── pcode2cpp/
│   ├── __init__.py
│   ├── ghidra.py
│   ├── _ghidra_export_runner.py
│   ├── context.py
│   ├── translate.py
│   └── verification.py
├── integrations/
│   ├── __init__.py
│   └── spore_decomp.py
└── tests/
    ├── __init__.py
    ├── test_context.py
    ├── test_ghidra.py
    ├── test_translate.py
    └── test_verification.py
```

## Status

Initial implementation. The Python unit tests can run without game files, Ghidra or a model server. The first real Ghidra export, Inkling translation and Spore proof have **not yet been tested on a local Spore installation**.

## License

MIT. External projects, Ghidra and model weights retain their own licenses.
