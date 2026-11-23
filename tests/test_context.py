import unittest

from pcode2cpp.context import context_json, validate_context


def sample():
    return {
        "schema_version": 1,
        "function": {"address": "0x672cf0", "name": "Test", "signature": "int Test(int)"},
        "program": {"name": "sample.exe"},
        "pseudocode": "int Test(int x) { return x + 1; }",
        "high_pcode": [{"operation": "INT_ADD", "inputs": ["a", "1"]}],
        "assembly": [{"address": "0x672cf0", "instruction": "INC EAX"}],
        "basic_blocks": [], "calls": [], "globals": [], "types": [], "variables": [],
    }


class ContextTests(unittest.TestCase):
    def test_complete_context_is_preserved(self):
        ctx = sample()
        ctx["calls"].append({"site": "0x672cf2", "target": None})
        ctx["special_extension"] = {"must_survive": 123}
        text = context_json(ctx)
        self.assertIn('"special_extension"', text)
        self.assertIn('"must_survive": 123', text)
        self.assertIn('"target": null', text)

    def test_no_pcode_rejected(self):
        ctx = sample()
        ctx["high_pcode"] = []
        with self.assertRaisesRegex(ValueError, "P-code is empty"):
            validate_context(ctx)

    def test_unknown_schema_rejected(self):
        ctx = sample()
        ctx["schema_version"] = 2
        with self.assertRaisesRegex(ValueError, "schema_version"):
            validate_context(ctx)


if __name__ == "__main__":
    unittest.main()
