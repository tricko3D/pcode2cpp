"""Separate Python process for a one-function PyGhidra export.

Open the existing GUI-style Ghidra project, without rerunning analysis or
creating an independent nested PyGhidra project. PyGhidra's legacy run_script
API is used because Ghidra 12.1's modern ghidra_script API does not accept
script_args.
"""

import argparse
from pathlib import Path
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-path", required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--program-name", required=True)
    parser.add_argument("--script", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--install-dir")
    args = parser.parse_args()

    import pyghidra

    pyghidra.run_script(
        binary_path=Path(args.binary),
        script_path=Path(args.script),
        project_location=Path(args.project_path),
        project_name=args.project_name,
        program_name=args.program_name,
        script_args=[args.output, args.address],
        analyze=False,
        nested_project_location=False,
        install_dir=Path(args.install_dir) if args.install_dir else None,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
