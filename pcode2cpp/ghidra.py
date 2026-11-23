"""Export one function from a previously analyzed Ghidra project."""

import os
from pathlib import Path
import subprocess
import sys

from .context import load_context

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ghidra_scripts" / "export_function.py"
RUNNER_MODULE = "pcode2cpp._ghidra_export_runner"


def _existing_project_directory(parent: Path, name: str) -> Path:
    """Resolve either GUI .gpr layout or PyGhidra's nested project layout."""
    direct = parent / (name + ".gpr")
    nested_dir = parent / name
    nested = nested_dir / (name + ".gpr")
    if direct.is_file() and nested.is_file():
        raise ValueError("Ambiguous Ghidra project: both direct and nested projects exist")
    if direct.is_file():
        return parent
    if nested.is_file():
        return nested_dir
    raise FileNotFoundError(
        f"No existing Ghidra project found at {direct} or {nested}. "
        "Check ghidra.project_path and ghidra.project_name."
    )


def export_function(address: int | str, destination: str | Path, settings: dict) -> dict:
    """Export without importing binaries, reanalyzing, or altering a project."""
    addr = int(address, 16) if isinstance(address, str) else int(address)
    if addr < 0:
        raise ValueError("Negative function address")

    dst = Path(destination).expanduser().resolve()
    parent = Path(settings["project_path"]).expanduser().resolve()
    name = settings["project_name"]
    if not isinstance(name, str) or not name or "/" in name or "\\" in name:
        raise ValueError("project_name must be a simple Ghidra project name")
    project_dir = _existing_project_directory(parent, name)

    binary_path = settings.get("program")
    program_name = settings.get("project_program")
    if not program_name and binary_path:
        program_name = Path(binary_path).name
    if (not isinstance(program_name, str) or not program_name or
            "/" in program_name or "\\" in program_name):
        raise ValueError("Set ghidra.project_program to the existing Ghidra program name")

    dst.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, "-m", RUNNER_MODULE,
        "--project-directory", str(project_dir),
        "--project-name", name,
        "--program-name", program_name,
        "--script", str(SCRIPT),
        "--output", str(dst),
        "--address", f"0x{addr:08x}",
    ]
    if settings.get("install_dir"):
        cmd.extend(["--install-dir", str(Path(settings["install_dir"]).expanduser().resolve())])

    # An old export must never be mistaken for a successful fresh export.
    dst.unlink(missing_ok=True)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900,
                          check=False, env=os.environ.copy(), cwd=str(ROOT))
    if proc.returncode != 0 or not dst.is_file():
        raise RuntimeError(f"Ghidra export failed (exit {proc.returncode}):\n{proc.stdout}\n{proc.stderr}")

    result = load_context(dst)
    if int(result["function"]["address"], 16) != addr:
        raise ValueError(f"Exported wrong function: {result['function']['address']}")
    return result
