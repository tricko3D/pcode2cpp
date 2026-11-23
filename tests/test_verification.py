import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from integrations.spore_decomp import SporeDecompBackend
from pcode2cpp.verification import Verdict


class SporeIntegrationTests(unittest.TestCase):
    def test_outside_source_never_touched(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend = SporeDecompBackend(Path(tmp))
            result = backend.verify(0x672CF0, Path("/tmp/outside.cpp"))
            self.assertEqual(result.verdict, Verdict.ERROR)

    def test_match_only_uses_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "match" / "slices" / "test.cpp"
            source.parent.mkdir(parents=True)
            source.write_text("// @ 0x00672cf0\nint f() { return 0; }\n")
            backend = SporeDecompBackend(root)
            def mock_run(cmd, **kwargs):
                self.assertEqual(cmd[-2:], ["--dry-run", "--no-quick"])
                return CompletedProcess(cmd, 0, "MATCH  0x00672cf0  f", "")
            with patch("integrations.spore_decomp.subprocess.run", side_effect=mock_run) as run:
                result = backend.verify(0x672cf0, source)
            self.assertEqual(result.verdict, Verdict.MATCH)
            self.assertEqual(run.call_count, 1)

    def test_nonmatch_runs_prover(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "candidate.cpp"
            source.write_text("// @ 0x00672cf0\nint f() { return 0; }\n")
            backend = SporeDecompBackend(root)
            calls = []
            def mock_run(cmd, **kwargs):
                calls.append(cmd)
                if "check.py" in cmd[1]:
                    return CompletedProcess(cmd, 1, "NO MATCH  0x00672cf0  f", "")
                return CompletedProcess(cmd, 0, "EQUIVALENT  0x00672cf0  angr_layer L1", "")
            with patch("integrations.spore_decomp.subprocess.run", side_effect=mock_run):
                result = backend.verify(0x672cf0, source)
            self.assertEqual(result.verdict, Verdict.EQUIVALENT)
            self.assertEqual(result.proof_method, "angr_layer")
            self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
