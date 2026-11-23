import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from pcode2cpp.ghidra import SCRIPT, ROOT, RUNNER_MODULE, export_function
from pcode2cpp._ghidra_export_runner import ensure_function
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


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.program = Mock()
        self.functions = self.program.getFunctionManager.return_value
        self.functions.getFunctionAt.return_value = None
        self.functions.getFunctionContaining.return_value = None
        self.functions.getFunctionCount.return_value = 295
        self.program.getMemory.return_value.getBlock.return_value.isExecute.return_value = True
        self.program.getName.return_value = "SporeApp.retail.analysis.bin"
        self.program.getImageBase.return_value = "00400000"
        self.pyghidra = Mock()
        self.entry = "00672cf0"

    def test_existing_function_does_not_trigger_analysis(self):
        expected = object()
        self.functions.getFunctionAt.return_value = expected
        result = ensure_function(self.program, self.entry, self.pyghidra)
        self.assertIs(result, expected)
        self.pyghidra.analyze.assert_not_called()
        self.program.save.assert_not_called()

    def test_missing_function_analyzes_and_saves_project(self):
        expected = object()
        self.functions.getFunctionAt.side_effect = [None, expected]
        self.functions.getFunctionCount.side_effect = [295, 85000]
        result = ensure_function(self.program, self.entry, self.pyghidra)
        self.assertIs(result, expected)
        self.pyghidra.analyze.assert_called_once_with(self.program)
        self.program.save.assert_called_once_with(
            "pcode2cpp auto-analysis", self.pyghidra.task_monitor.return_value
        )

    def test_missing_function_with_analysis_disabled_raises_without_mutations(self):
        with self.assertRaisesRegex(RuntimeError, "disabled"):
            ensure_function(self.program, self.entry, self.pyghidra, False)
        self.pyghidra.analyze.assert_not_called()
        self.program.save.assert_not_called()

    def test_target_outside_executable_memory_is_rejected(self):
        self.program.getMemory.return_value.getBlock.return_value = None
        with self.assertRaisesRegex(RuntimeError, "not inside executable memory"):
            ensure_function(self.program, self.entry, self.pyghidra)
        self.pyghidra.analyze.assert_not_called()

    def test_target_inside_another_function_is_rejected(self):
        other = Mock()
        other.getName.return_value = "other_function"
        other.getEntryPoint.return_value = "00672ca0"
        self.functions.getFunctionContaining.return_value = other
        with self.assertRaisesRegex(RuntimeError, "lies inside function"):
            ensure_function(self.program, self.entry, self.pyghidra)
        self.pyghidra.analyze.assert_not_called()

    def test_no_guessed_function_created_after_full_analysis(self):
        self.functions.getFunctionAt.side_effect = [None, None]
        with self.assertRaisesRegex(RuntimeError, "No guessed function was created"):
            ensure_function(self.program, self.entry, self.pyghidra)
        self.pyghidra.analyze.assert_called_once_with(self.program)
        self.program.save.assert_called_once()
        self.program.getFunctionManager.return_value.createFunction.assert_not_called()

    def test_explicit_no_analysis_option_is_forwarded(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "spore.gpr").touch()
            dst = root / "context.json"
            settings = {
                "project_path": tmp,
                "project_name": "spore",
                "project_program": "SporeApp.exe",
                "analyze_if_missing": False,
            }

            def fake_run(args, **kwargs):
                self.assertIn("--no-auto-analysis", args)
                self.assertEqual(kwargs["timeout"], 900)
                dst.write_text(json.dumps(sample()), encoding="utf-8")
                return subprocess.CompletedProcess(args, 0, "ok", "")

            with patch("pcode2cpp.ghidra.subprocess.run", side_effect=fake_run):
                export_function(0x00672CF0, dst, settings)


class NotebookTests(unittest.TestCase):
    def test_first_code_cell_is_self_contained_and_notebook_compiles(self):
        notebook = json.loads(
            (ROOT / "notebooks" / "reconstruct.ipynb").read_text(encoding="utf-8")
        )
        cells = [cell for cell in notebook["cells"] if cell["cell_type"] == "code"]
        for index, cell in enumerate(cells):
            source = "".join(cell["source"])
            compile(source, f"notebook-cell-{index}", "exec")
        first = "".join(cells[0]["source"])
        self.assertIn("from pcode2cpp.ghidra import export_function", first)
        self.assertIn("CONFIG = json.loads(", first)
        self.assertIn("ADDRESS = 0x00672CF0", first)
        self.assertIn("context = export_function(", first)


if __name__ == "__main__":
    unittest.main()
