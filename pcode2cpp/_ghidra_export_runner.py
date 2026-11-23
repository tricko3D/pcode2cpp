"""Open an existing Ghidra project and export one function without analysis.

Runs as a subprocess of the pcode2cpp notebook in the same Python environment.
Only a preexisting .gpr project and program are opened: no binary imports,
new project creation, or automatic analysis.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import sys


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

    import pyghidra

    if args.install_dir:
        pyghidra.start(install_dir=Path(args.install_dir).resolve())
    else:
        pyghidra.start()

    # Import the exporter as a normal Python module, not a GhidraScript.
    # Its export_one function uses the same API as the original GUI exporter.
    spec = importlib.util.spec_from_file_location("_pcode2cpp_ghidra_export", args.script)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load Ghidra exporter: " + args.script)
    exporter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exporter)

    with pyghidra.open_project(project_directory, args.project_name, create=False) as project:
        with pyghidra.program_context(project, "/" + args.program_name) as program:
            space = program.getAddressFactory().getDefaultAddressSpace()
            entry = space.getAddress(int(args.address, 16))
            context = exporter.export_one(program, entry, pyghidra.task_monitor())

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(context, indent=2, sort_keys=True, ensure_ascii=False),
                      encoding="utf-8")
    print("pcode2cpp exported %s (%d P-code operations, %d calls)" %
          (args.address, len(context["high_pcode"]), len(context["calls"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
