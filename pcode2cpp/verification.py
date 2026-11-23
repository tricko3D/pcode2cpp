"""A small optional contract for external project-specific verifiers."""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol


class Verdict(str, Enum):
    MATCH = "match"
    EQUIVALENT = "equivalent"
    REFUTED = "refuted"
    UNKNOWN = "unknown"
    COMPILE_FAILED = "compile_failed"
    ERROR = "error"


@dataclass(frozen=True)
class VerificationResult:
    verdict: Verdict
    details: str
    proof_method: str | None = None
    compiler_output: str = ""


class VerificationBackend(Protocol):
    def verify(self, address: int, source: Path) -> VerificationResult:
        """Inspect a candidate already prepared for the backend's build environment."""
        ...
