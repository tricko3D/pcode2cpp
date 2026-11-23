"""Export a function from an existing Ghidra project.

The notebook uses this module in a subprocess to isolate the Ghidra JVM.
On a missing function entry, run and save full Ghidra auto-analysis once
before retrying. Never create a project, import a binary, or invent a
function boundary.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import sys


def ensure_function(program, entry, pyghidra, analyze_if_missing=True):
    """Return a real Ghidra function, analyzing an incomplete project if needed."""
    functions = program.getFunctionManager()
    found = functions.getFunctionAt(entry)
    if found is not None:
        return found

    memory_block = program.getMemory().getBlock(entry)
    if memory_block is None or not memory_block.isExecute():
        raise RuntimeError(
            "Target %s is not inside executable memory in %s (image base %s). "
            "Check the selected binary and the retail function address."
            % (entry, program.getName(), program.getImageBase())
        )

    containing = functions.getFunctionContaining(entry)
    if containing is not None:
        raise RuntimeError(
            "Target %s lies inside function %s at %s. "
            "It cannot be exported as a separate function entry."
            % (entry, containing.getName(), containing.getEntryPoint())
        )

    if not analyze_if_missing:
        raise RuntimeError(
            "No function at %s in %s (total functions: %d); "
            "automatic analysis is disabled in config.json."
            % (entry, program.getName(), functions.getFunctionCount())
        )

    before = functions.getFunctionCount()
    print(
        "pcode2cpp: No function at %s; %d functions in project. "
        "Running Ghidra auto-analysis and saving results..."
        % (entry, before),
        flush=True,
    )

    pyghidra.analyze(program)
    program.save("pcode2cpp auto-analysis", pyghidra.task_monitor())

    after = functions.getFunctionCount()
    found = functions.getFunctionAt(entry)
    print("pcode2cpp: Analysis saved (%d -> %d functions)." % (before, after), flush=True)

    if found is None:
        instruction = program.getListing().getInstructionContaining(entry)
        containing = functions.getFunctionContaining(entry)
        raise RuntimeError(
            "Full Ghidra analysis completed, but %s is still not a function entry "
            "in %s (image base %s, functions %d, instruction %s, containing function %s). "
            "The project may contain the wrong retail build or Ghidra may not "
            "have discovered this particular function. No guessed function was created."
            % (entry, program.getName(), program.getImageBase(), after,
               instruction, containing)
        )

    return found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-directory", required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--program-name", required=True)
    parser.add_argument("--script", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--install-dir")
    parser.add_argument("--no-auto-analysis", action="store_true")
    args = parser.parse_args()

    project_directory = Path(args.project_directory).resolve()
    if not (project_directory / (args.project_name + ".gpr")).is_file():
        parser.error("Ghidra project does not exist in " + str(project_directory))

    import pyghidra

    if args.install_dir:
        pyghidra.start(install_dir=Path(args.install_dir).resolve())
    else:
        pyghidra.start()

    spec = importlib.util.spec_from_file_location("_pcode2cpp_ghidra_export", args.script)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load Ghidra exporter: " + args.script)
    exporter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exporter)

    with pyghidra.open_project(project_directory, args.project_name, create=False) as project:
        with pyghidra.program_context(project, "/" + args.program_name) as program:
            space = program.getAddressFactory().getDefaultAddressSpace()
            entry = space.getAddress(int(args.address, 16))
            ensure_function(program, entry, pyghidra,
                            analyze_if_missing=not args.no_auto_analysis)
            context = exporter.export_one(program, entry, pyghidra.task_monitor())

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(context, indent=2, sort_keys=True, ensure_ascii=False),
                      encoding="utf-8")
    print("pcode2cpp: Exported %s (%d P-code operations, %d calls)" %
          (args.address, len(context["high_pcode"]), len(context["calls"])), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
