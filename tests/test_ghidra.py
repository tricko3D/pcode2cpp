import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pcode2cpp.ghidra import SCRIPT, ROOT, RUNNER_MODULE, export_function
from tests.test_context import sample


class GhidraTests(unittest.TestCase):
    def test_nested_wsl_project_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "spore"
            nested.mkdir()
            (nested / "spore.gpr").touch()
            settings = {"project_path": tmp, "project_name": "spore",
                        "program": "/somewhere/SporeApp.analysis.bin"}
            dst = root / "case" / "context.json"

            def fake_run(args, **kwargs):
                self.assertEqual(args[1:3], ["-m", RUNNER_MODULE])
                self.assertEqual(kwargs["cwd"], str(ROOT))
                self.assertEqual(args[args.index("--project-directory") + 1], str(nested))
                self.assertEqual(args[args.index("--program-name") + 1],
                                 "SporeApp.analysis.bin")
                self.assertIn(str(SCRIPT), args)
                self.assertNotIn("--skip-analysis", args)
                self.assertNotIn("--binary", args)
                self.assertEqual(args[-1], "0x00672cf0")
                dst.write_text(json.dumps(sample()), encoding="utf-8")
                from subprocess import CompletedProcess
                return CompletedProcess(args, 0, "ok", "")

            with patch("pcode2cpp.ghidra.subprocess.run", side_effect=fake_run) as run:
                result = export_function(0x00672CF0, dst, settings)
            self.assertEqual(result["function"]["address"], "0x672cf0")
            self.assertEqual(run.call_count, 1)

    def test_gui_project_export_without_binary_on_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "spore.gpr").touch()
            settings = {"project_path": tmp, "project_name": "spore",
                        "project_program": "SporeApp.exe",
                        "program": "C:/not/present/SporeApp.exe"}
            dst = root / "context.json"

            def fake_run(args, **kwargs):
                self.assertEqual(args[args.index("--project-directory") + 1], str(root))
                self.assertEqual(args[args.index("--program-name") + 1], "SporeApp.exe")
                dst.write_text(json.dumps(sample()), encoding="utf-8")
                from subprocess import CompletedProcess
                return CompletedProcess(args, 0, "ok", "")

            with patch("pcode2cpp.ghidra.subprocess.run", side_effect=fake_run):
                export_function(0x00672CF0, dst, settings)

    def test_missing_project_does_not_create_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("pcode2cpp.ghidra.subprocess.run") as run:
                with self.assertRaises(FileNotFoundError):
                    export_function(0x672cf0, Path(tmp) / "out.json",
                                    {"project_path": tmp, "project_name": "spore",
                                     "project_program": "SporeApp.exe"})
                run.assert_not_called()

    def test_ambiguous_direct_and_nested_project_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "spore.gpr").touch()
            (root / "spore").mkdir()
            (root / "spore" / "spore.gpr").touch()
            with self.assertRaises(ValueError):
                export_function(0x672cf0, root / "out.json",
                                {"project_path": tmp, "project_name": "spore",
                                 "project_program": "SporeApp.exe"})

    def test_missing_program_name_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "spore.gpr").touch()
            with self.assertRaises(ValueError):
                export_function(0x672cf0, root / "out.json",
                                {"project_path": tmp, "project_name": "spore"})


if __name__ == "__main__":
    unittest.main()
