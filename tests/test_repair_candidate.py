"""Repair-context tests without contacting the local model."""
import unittest
import io
import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

from scripts import repair_candidate
from scripts.probe_body import PREFIX
from scripts.repair_candidate import concise_errors, extract_body, make_messages


class RepairCandidateTests(unittest.TestCase):
    def test_body_extraction(self):
        body = "param_1[4] = param_1 + 5;\nreturn param_1;"
        self.assertEqual(extract_body(PREFIX + body + "\n}\n"), body)

    def test_unexpected_signature_rejected(self):
        with self.assertRaises(ValueError):
            extract_body("int f() { return 0; }")

    def test_only_distinct_compiler_errors_are_forwarded(self):
        diagnostic = """/tmp/a.cpp:6:22: error: incompatible pointer assignment
    6 | a = b;
/tmp/a.cpp:7:12: error: invalid conversion
/tmp/a.cpp:6:22: error: incompatible pointer assignment
/tmp/a.cpp:3:4: note: some note
"""
        self.assertEqual(
            concise_errors(diagnostic),
            ["line 6:22: error: incompatible pointer assignment", "line 7:12: error: invalid conversion"],
        )

    def test_short_repair_context_does_not_include_ghidra_dump(self):
        messages = make_messages("return param_1;", ["line 6:22: error: cannot assign pointer"])
        self.assertEqual([msg["role"] for msg in messages], ["system", "user", "assistant", "user"])
        self.assertNotIn("High P-code", str(messages))
        self.assertNotIn("Original assembly", str(messages))
        self.assertIn("return param_1;", messages[2]["content"])
        self.assertIn("line 6:22", messages[3]["content"])

    @unittest.skipUnless(shutil.which("clang++"), "Clang required")
    def test_one_repair_compiles_without_overwriting_original(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            original = directory / "initial.cpp"
            original_content = PREFIX + (
                "param_1[4] = param_1 + 5;\n"
                "FUN_00672750(param_1, param_2[0], param_2[1]);\n"
                "return param_1;\n}\n"
            )
            original.write_text(original_content)
            (directory / "config.json").write_text(json.dumps({"llm": {"model": "local"}}))
            corrected = (
                "param_1[4] = reinterpret_cast<int>(param_1 + 5);\n"
                "FUN_00672750(param_1, reinterpret_cast<int*>(param_2[0]), "
                "reinterpret_cast<int*>(param_2[1]));\n"
                "return param_1;"
            )
            event = {"choices": [{"delta": {"content": json.dumps({"body": corrected})}, "finish_reason": "stop"}]}
            stream = io.BytesIO(("data: " + json.dumps(event) + "\n\ndata: [DONE]\n").encode())
            captured = []

            def fake_urlopen(request, timeout=None):
                captured.append(json.loads(request.data))
                return stream

            with patch.object(repair_candidate, "ROOT", directory), patch.object(repair_candidate, "urlopen", fake_urlopen):
                self.assertEqual(repair_candidate.run(original), 0)
            self.assertEqual(original.read_text(), original_content)
            self.assertEqual(len(captured), 1)
            self.assertNotIn("tools", captured[0])
            self.assertEqual([m["role"] for m in captured[0]["messages"]], ["system", "user", "assistant", "user"])
            repaired = directory / "initial_repair001.cpp"
            self.assertTrue(repaired.is_file())
            self.assertIn("reinterpret_cast", repaired.read_text())
            self.assertIn("Status: PASS", (directory / "initial_repair001.compile.log").read_text())


if __name__ == "__main__":
    unittest.main()
