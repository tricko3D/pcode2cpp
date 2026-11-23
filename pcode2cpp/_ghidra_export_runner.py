"""Read-only export of an existing Ghidra function.

Never import a binary, create a function, run analysis, or save changes to
the Ghidra project. The notebook runs this module in a subprocess so the
Ghidra JVM is isolated from its Python kernel.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import sys


def require_function(program, entry):
    functions = program.getFunctionManager()
    found = functions.getFunctionAt(entry)
    if found is not None:
        return found

    listing = program.getListing()
    memory = program.getMemory()
    block = memory.getBlock(entry)
    containing = functions.getFunctionContaining(entry)
    instruction = listing.getInstructionContaining(entry)
    raise RuntimeError(
        "No function starts at %s in %s. Image base: %s; recognized "
        "functions: %d; memory block: %s; instruction: %s; containing "
        "function: %s. The exporter will not reanalyze or change your "
        "Ghidra project. This address must be a recognized function "
        "entry before High P-code can be exported."
        % (entry, program.getName(), program.getImageBase(),
           functions.getFunctionCount(), block, instruction, containing)
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-directory", required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--program-name", required=True)
    parser.add_argument("--script", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--install-dir")
    args = parser.parse_args()

    project_directory = Path(args.project_directory).resolve()
    if not (project_directory / (args.project_name + ".gpr")).is_file():
        parser.error("Ghidra project does not exist in " + str(project_directory))

    print("pcode2cpp: Starting PyGhidra (read-only)...", flush=True)
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

    print("pcode2cpp: Opening existing Ghidra project...", flush=True)
    with pyghidra.open_project(project_directory, args.project_name, create=False) as project:
        with pyghidra.program_context(project, "/" + args.program_name) as program:
            print("pcode2cpp: Reading %s at %s..." %
                  (program.getName(), args.address), flush=True)
            space = program.getAddressFactory().getDefaultAddressSpace()
            entry = space.getAddress(int(args.address, 16))
            require_function(program, entry)
            context = exporter.export_one(program, entry, pyghidra.task_monitor())

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(context, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    print("pcode2cpp: Exported %s (%d P-code operations, %d calls)" %
          (args.address, len(context["high_pcode"]), len(context["calls"])), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
