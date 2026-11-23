#!/usr/bin/env python3
"""Type-check a generated C++ candidate without contacting an LLM.

Uses Clang's 32-bit Windows/MSVC target to honor __thiscall and pointer sizes.
This is a compile-only check, not a link, byte match, or behavioral proof.
"""

import argparse
from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import tempfile

# The fixed probe prefix includes <cstdint>. Cross-target Clang running on
# Linux often cannot find the Windows C++ standard library. Provide only the
# fixed-width integer aliases needed by this standalone probe; do not silently
# substitute a whole standard library or modify the candidate itself.
CSTDINT_SHIM = """#pragma once
using int8_t = signed char;
using uint8_t = unsigned char;
using int16_t = short;
using uint16_t = unsigned short;
using int32_t = int;
using uint32_t = unsigned int;
using int64_t = long long;
using uint64_t = unsigned long long;
namespace std {
    using ::int8_t; using ::uint8_t;
    using ::int16_t; using ::uint16_t;
    using ::int32_t; using ::uint32_t;
    using ::int64_t; using ::uint64_t;
}
"""


@dataclass(frozen=True)
class CompileResult:
    passed: bool
    diagnostics_path: Path
    diagnostics: str
    status: str


def check_candidate(candidate: Path) -> CompileResult:
    candidate = Path(candidate).resolve()
    if not candidate.is_file():
        raise FileNotFoundError(f"Candidate not found: {candidate}")

    diagnostics_path = candidate.with_suffix(".compile.log")
    compiler = next(
        (path for name in ("clang++", "clang++-20", "clang++-19", "clang++-18", "clang++-17", "clang++-16")
         if (path := shutil.which(name))),
        None,
    )
    if compiler is None:
        diagnostics = "Clang is unavailable: install clang++ in WSL to type-check this candidate.\n"
        status = "UNAVAILABLE"
    else:
        with tempfile.TemporaryDirectory(prefix="pcode2cpp-check-") as directory:
            header = Path(directory) / "cstdint"
            header.write_text(CSTDINT_SHIM, encoding="utf-8")
            command = [
                compiler,
                "--target=i686-pc-windows-msvc",
                "-fms-extensions",
                "-std=c++17",
                "-fsyntax-only",
                "-nostdinc++",
                "-isystem", directory,
                str(candidate),
            ]
            try:
                completed = subprocess.run(
                    command, capture_output=True, text=True, timeout=30, check=False
                )
            except subprocess.TimeoutExpired:
                diagnostics = "Compiler timed out after 30 seconds.\n"
                status = "TIMEOUT"
            except OSError as exc:
                diagnostics = f"Compiler could not be launched: {exc}\n"
                status = "UNAVAILABLE"
            else:
                diagnostics = (completed.stdout + completed.stderr).strip()
                status = "PASS" if completed.returncode == 0 else "FAIL"
                if not diagnostics:
                    diagnostics = "No compiler diagnostics."

    diagnostics_path.write_text(f"Status: {status}\n{diagnostics}\n", encoding="utf-8")
    return CompileResult(status == "PASS", diagnostics_path, diagnostics, status)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path, help="Existing .cpp candidate; never regenerated or modified")
    args = parser.parse_args()
    try:
        result = check_candidate(args.candidate)
    except FileNotFoundError as exc:
        parser.error(str(exc))
    print(f"Compiler check: {result.status}")
    print(f"Diagnostics: {result.diagnostics_path}")
    if not result.passed:
        print(result.diagnostics)
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
