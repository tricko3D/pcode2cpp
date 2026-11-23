"""One-off Spore equivalence integration: verify our object is selected, not upstream."""
import tempfile
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

from scripts.probe_body import PREFIX
from scripts.prove_spore_candidate import prepare_source, verify_compiled_candidate


BODY = (
    "param_1[4] = (int)(param_1 + 5);\n"
    "param_1[2] = (int)(param_1 + 0x15);\n"
    "param_1[1] = (int)(param_1 + 5);\n"
    "*param_1 = (int)(param_1 + 5);\n"
    "*(uint16_t*)(param_1 + 5) = 0;\n"
    "FUN_00672750(param_1, (int*)param_2[0], (int*)param_2[1]);\n"
    "param_1[0x15] = param_2[0x15];\n"
    "return param_1;"
)


class TestEquivalenceCandidate(unittest.TestCase):
    def test_prepares_only_ignored_work_and_reuses_same_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / "candidate.cpp"
            candidate.write_text(PREFIX + BODY + "\n}\n", encoding="utf-8")
            prepared = prepare_source(root, candidate)
            self.assertTrue(prepared.is_file())
            self.assertEqual(prepared, prepare_source(root, candidate))
            self.assertIn("work/pcode2cpp_checks", str(prepared))
            self.assertIn("param_1[0x15] = param_2[0x15];", prepared.read_text())
            self.assertEqual(candidate.read_text(), PREFIX + BODY + "\n}\n")

    def test_prover_receives_compiled_candidate_not_tracked_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "work").mkdir()
            (repo / "work/SporeApp.analysis.bin").write_bytes(b"fixture")
            src = repo / "work/pcode2cpp_checks/candidate.cpp"
            src.parent.mkdir()
            src.write_text("fixture")

            original_called = []
            def original(va, flags=None):
                original_called.append(va)
                return object()

            func = types.ModuleType("func")
            func.our_func = original
            ours = types.SimpleNamespace(code=b"candidate-bytecode", meta={})
            func.obj_func = lambda obj, sym: ours

            task = types.ModuleType("task")
            task.fingerprint = lambda va: {"size": 57}

            slice_mod = types.ModuleType("slice")
            slice_mod.choose_flags = lambda ident, va: (["/O2", "/MD", "/Gy", "/EHsc", "/TP"], "fixture")
            slice_mod.compile_obj = lambda src, flags: ("/tmp/candidate.obj", "")

            coff = types.ModuleType("coff")
            coff.Coff = lambda path: types.SimpleNamespace(functions=lambda: {
                "?FUN_00672cf0@InklingCandidate_s00672cf0@@QAEPAHPAH@Z": None
            })

            def prove_run(va, layers, timeout, k_mutants):
                self.assertIs(func.our_func(va), ours)
                self.assertEqual(ours.meta["src"], "work/pcode2cpp_checks/candidate.cpp")
                self.assertEqual(layers, ["rename", "angr_layer"])
                self.assertEqual(k_mutants, 5)
                return {"verdict": "UNKNOWN", "level": "L1"}

            prove = types.ModuleType("prove")
            prove.run = prove_run

            modules = {"func": func, "task": task, "slice": slice_mod, "coff": coff, "prove": prove}
            with patch.dict(sys.modules, modules):
                result = verify_compiled_candidate(repo, src, ["rename", "angr_layer"], 300, 5)
            self.assertEqual(result, 1)
            self.assertIs(func.our_func, original)
            self.assertEqual(original_called, [])


if __name__ == "__main__":
    unittest.main()
