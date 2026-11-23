import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pcode2cpp.ghidra import SCRIPT, export_function
from tests.test_context import sample


class GhidraTests(unittest.TestCase):
    def test_export_invokes_existing_project_and_validates_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            program = root / "input.bin"
            program.write_bytes(b"dummy")
            settings = {"project_path": tmp, "project_name": "spore", "program": str(program), "pyghidra": "pyghidra"}
            dst = root / "case" / "context.json"

            def fake_run(args, **kwargs):
                self.assertIn("--skip-analysis", args)
                self.assertIn(str(SCRIPT), args)
                self.assertEqual(args[-1], "0x00672cf0")
                dst.write_text(json.dumps(sample()), encoding="utf-8")
                from subprocess import CompletedProcess
                return CompletedProcess(args, 0, "ok", "")

            with patch("pcode2cpp.ghidra.subprocess.run", side_effect=fake_run) as run:
                result = export_function(0x00672CF0, dst, settings)
            self.assertEqual(result["function"]["address"], "0x672cf0")
            self.assertEqual(run.call_count, 1)

    def test_missing_program_fails_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                export_function(0x672cf0, Path(tmp) / "out.json", {"project_path": tmp, "program": "/not/here.exe", "project_name": "spore"})


if __name__ == "__main__":
    unittest.main()
