"""Standalone syntax-check tests; no model server or Spore toolchain needed."""
import shutil
import tempfile
from pathlib import Path
import unittest

from scripts.check_candidate import check_candidate


PREFIX = (
    "#include <cstdint>\n"
    "int* __thiscall helper(int* self, int* begin, int* end);\n"
    "int* __thiscall example(int* a, int* b) {\n"
)


@unittest.skipUnless(shutil.which("clang++"), "Clang is not installed")
class CompileCandidateTests(unittest.TestCase):
    def test_rejects_pointer_type_errors_without_changing_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "candidate.cpp"
            source = PREFIX + "a[0] = a + 5;\nhelper(a, b[0], b[1]);\nreturn a;\n}\n"
            path.write_text(source, encoding="utf-8")
            result = check_candidate(path)
            self.assertEqual(result.status, "FAIL")
            self.assertIn("error:", result.diagnostics)
            self.assertEqual(path.read_text(encoding="utf-8"), source)
            self.assertTrue(result.diagnostics_path.is_file())

    def test_accepts_corrected_pointer_types(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "candidate.cpp"
            path.write_text(
                PREFIX
                + "a[0] = reinterpret_cast<int>(a + 5);\n"
                + "helper(a, reinterpret_cast<int*>(b[0]), reinterpret_cast<int*>(b[1]));\n"
                + "return a;\n}\n",
                encoding="utf-8",
            )
            result = check_candidate(path)
            self.assertEqual(result.status, "PASS", result.diagnostics)


if __name__ == "__main__":
    unittest.main()
