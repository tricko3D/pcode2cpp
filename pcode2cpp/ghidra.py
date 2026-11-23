"""Export a function from an existing Ghidra GUI project using PyGhidra."""

import os
from pathlib import Path
import subprocess
import sys

from .context import load_context

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ghidra_scripts" / "export_function.py"
RUNNER = ROOT / "pcode2cpp" / "_ghidra_export_runner.py"


def export_function(address: int | str, destination: str | Path, settings: dict) -> dict:
    """Export one previously analyzed function, without triggering analysis."""
    addr = int(address, 16) if isinstance(address, str) else int(address)
    if addr < 0:
        raise ValueError("Negative function address")

    dst = Path(destination).expanduser().resolve()
    dst.parent.mkdir(parents=True, exist_ok=True)
    project_path = Path(settings["project_path"]).expanduser().resolve()
    if not project_path.is_dir():
        raise FileNotFoundError(f"Ghidra project parent directory not found: {project_path}")

    name = settings["project_name"]
    locator = project_path / (name + ".gpr")
    if not locator.is_file():
        raise FileNotFoundError(f"Existing Ghidra project not found: {locator}")

    binary = Path(settings["program"]).expanduser().resolve()
    if not binary.is_file():
        raise FileNotFoundError(f"Ghidra program binary not found: {binary}")
    program_name = settings.get("project_program") or binary.name
    if not isinstance(program_name, str) or not program_name or "/" in program_name or "\\" in program_name:
        raise ValueError("project_program must be the program name at the Ghidra project root")

    cmd = [
        sys.executable, str(RUNNER),
        "--project-path", str(project_path),
        "--project-name", name,
        "--binary", str(binary),
        "--program-name", program_name,
        "--script", str(SCRIPT),
        "--output", str(dst),
        "--address", f"0x{addr:08x}",
    ]
    if settings.get("install_dir"):
        cmd.extend(["--install-dir", str(Path(settings["install_dir"]).expanduser().resolve())])

    # A previous JSON must never be mistaken for a successful fresh export.
    dst.unlink(missing_ok=True)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900,
                          check=False, env=os.environ.copy())
    if proc.returncode != 0 or not dst.is_file():
        raise RuntimeError(f"Ghidra export failed (exit {proc.returncode}):\n{proc.stdout}\n{proc.stderr}")

    result = load_context(dst)
    if int(result["function"]["address"], 16) != addr:
        raise ValueError(f"Exported wrong function: {result['function']['address']}")
    return result
