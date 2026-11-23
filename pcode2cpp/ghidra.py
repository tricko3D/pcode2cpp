"""Launch the independent PyGhidra exporter against an already analyzed project."""

import os
from pathlib import Path
import subprocess

from .context import load_context


SCRIPT = Path(__file__).resolve().parent.parent / "ghidra_scripts" / "export_function.py"


def export_function(address: int | str, destination: str | Path, settings: dict) -> dict:
    """Run exactly one export; no project analysis or background execution."""
    addr = int(address, 16) if isinstance(address, str) else int(address)
    if addr < 0:
        raise ValueError("Negative function address")
    path = Path(destination).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    project_path = Path(settings["project_path"]).expanduser().resolve()
    program = Path(settings["program"]).expanduser().resolve()
    if not program.is_file():
        raise FileNotFoundError(f"Ghidra program not found: {program}")
    if not project_path.is_dir():
        raise FileNotFoundError(f"Ghidra project directory not found: {project_path}")
    cmd = [
        settings.get("pyghidra", "pyghidra"),
        "--project-path", str(project_path),
        "--project-name", settings["project_name"],
        "--skip-analysis", str(program), str(SCRIPT), str(path), f"0x{addr:08x}",
    ]
    env = os.environ.copy()
    if settings.get("install_dir"):
        env["GHIDRA_INSTALL_DIR"] = str(Path(settings["install_dir"]).expanduser().resolve())
    # An old JSON must never be mistaken for a successful new export.
    path.unlink(missing_ok=True)
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=900, check=False)
    if proc.returncode != 0 or not path.is_file():
        raise RuntimeError(f"Ghidra export failed (exit {proc.returncode}):\n{proc.stdout}\n{proc.stderr}")
    result = load_context(path)
    if int(result["function"]["address"], 16) != addr:
        raise ValueError(f"Exported wrong function: {result['function']['address']}")
    return result
