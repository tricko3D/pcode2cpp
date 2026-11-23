"""Opt-in adapter to the EXISTING Spore checker and equivalence prover.

The candidate must be manually placed into the proper compilation unit of a
SEPARATE Spore working copy first. This adapter NEVER replaces or edits source.
"""

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess

from pcode2cpp.verification import Verdict, VerificationResult


@dataclass
class SporeDecompBackend:
    repo_path: Path
    python: str = ".venv/bin/python"
    timeout_seconds: int = 600

    def _run(self, script: str, address: int, *args: str) -> subprocess.CompletedProcess:
        python_path = Path(self.python)
        executable = str(self.repo_path / python_path) if not python_path.is_absolute() else str(python_path)
        return subprocess.run(
            [executable, str(self.repo_path / script), f"0x{address:08x}", *args],
            cwd=self.repo_path, text=True, capture_output=True, timeout=self.timeout_seconds, check=False,
        )

    def verify(self, address: int, source: Path) -> VerificationResult:
        root = self.repo_path.expanduser().resolve()
        path = Path(source).expanduser().resolve()
        try:
            path.relative_to(root)
        except ValueError:
            return VerificationResult(Verdict.ERROR, "Source must already be installed in a dedicated Spore checkout; no automatic copying")
        if not path.is_file():
            return VerificationResult(Verdict.ERROR, f"Source file not found: {path}")
        marker = re.compile(rf"(?mi)^//\s*@\s*0x0*{address:x}\b")
        if not marker.search(path.read_text(encoding="utf-8", errors="replace")):
            return VerificationResult(Verdict.ERROR, f"Source does not contain // @ 0x{address:08x} marker")
        try:
            check = self._run("tools/contrib/check.py", address, "--dry-run", "--no-quick")
            check_output = (check.stdout + "\n" + check.stderr).strip()
            if re.search(r"(?m)^MATCH\s+0x", check.stdout):
                return VerificationResult(Verdict.MATCH, check_output, compiler_output=check_output)
            if re.search(r"(?m)^COMPILE FAILED", check.stdout):
                return VerificationResult(Verdict.COMPILE_FAILED, check_output, compiler_output=check_output)
            if not re.search(r"(?m)^NO MATCH\s+0x", check.stdout):
                return VerificationResult(Verdict.ERROR, check_output, compiler_output=check_output)
            proof = self._run("tools/contrib/prove.py", address, "--json")
            proof_output = (proof.stdout + "\n" + proof.stderr).strip()
            m = re.search(r"(?m)^(MATCH|EQUIVALENT|REFUTED|UNKNOWN|ERROR)\s+0x[0-9a-fA-F]+\b(?:\s+(\w+))?", proof.stdout)
            if m:
                verdict = Verdict(m.group(1).lower())
                return VerificationResult(verdict, proof_output, proof_method=m.group(2) if verdict == Verdict.EQUIVALENT else None, compiler_output=check_output)
            return VerificationResult(Verdict.ERROR, proof_output, compiler_output=check_output)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return VerificationResult(Verdict.ERROR, str(exc))
