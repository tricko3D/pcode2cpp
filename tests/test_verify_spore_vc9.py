"""The VC9 wrapper changes only the ABI syntax, never the candidate's logic."""
import unittest

from scripts.probe_body import PREFIX
from scripts.verify_spore_vc9 import candidate_body, render_vc9_source


REPAIRED_BODY = (
    "param_1[4] = (int)(param_1 + 5);\n"
    "param_1[2] = (int)(param_1 + 0x15);\n"
    "param_1[1] = (int)(param_1 + 5);\n"
    "*param_1 = (int)(param_1 + 5);\n"
    "*(uint16_t*)(param_1 + 5) = 0;\n"
    "FUN_00672750(param_1, (int*)param_2[0], (int*)param_2[1]);\n"
    "param_1[0x15] = param_2[0x15];\n"
    "return param_1;"
)


class Vc9WrapperTests(unittest.TestCase):
    def test_prepends_real_thiscall_member_and_preserves_stores(self):
        cpp = render_vc9_source(PREFIX + REPAIRED_BODY + "\n}\n")
        self.assertIn("typedef unsigned short uint16_t;", cpp)
        self.assertIn("// @ 0x00672cf0", cpp)
        self.assertIn("int* param_1 = (int*)this;", cpp)
        self.assertIn("this->FUN_00672750((int*)param_2[0], (int*)param_2[1]);", cpp)
        self.assertIn("param_1[0x15] = param_2[0x15];", cpp)
        self.assertNotIn("#include <cstdint>", cpp)
        self.assertIn("return param_1;", cpp)

    def test_rejects_other_signatures_or_mismatched_callee(self):
        with self.assertRaises(ValueError):
            render_vc9_source("int f(){return 0;}")
        with self.assertRaises(ValueError):
            candidate_body(PREFIX + REPAIRED_BODY.replace("FUN_00672750(param_1,", "FUN_00672750(param_2,") + "\n}\n")


if __name__ == "__main__":
    unittest.main()
