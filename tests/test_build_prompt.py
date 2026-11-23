import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pcode2cpp.context import validate_context

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_prompt.py"


def example():
    return validate_context({
        "schema_version": 1,
        "program": {"name": "test.exe", "language": "x86:LE:32:default", "compiler_spec": "windows"},
        "function": {
            "address": "0x672cf0", "name": "FUN_00672cf0",
            "end": "0x672cf5", "signature": "int FUN_00672cf0(int x)",
            "calling_convention": "__cdecl",
            "parameters": [{"name": "x", "type": {"name": "int"}, "storage": "EAX"}],
            "locals": []
        },
        "pseudocode": "int FUN_00672cf0(int x) {\n  return x + 1;\n}",
        "assembly": [
            {"address": "0x672cf0", "instruction": "MOV EAX,ECX", "bytes": "89c8"},
            {"address": "0x672cf2", "instruction": "INC EAX", "bytes": "40"},
        ],
        "high_pcode": [
            {"address": "0x672cf2", "order": 0, "block_index": 0,
             "operation": "INT_ADD", "output": {"storage": "(register, 0x0, 4)"},
             "inputs": [{"storage": "(register, 0x0, 4)"}, {"storage": "(const, 0x1, 4)"}]}
        ],
        "basic_blocks": [{"index": 0, "start": "0x672cf0", "end": "0x672cf5", "successors": []}],
        "calls": [{"site": "0x672cf4", "target": None, "instruction": "CALL EAX"}],
        "globals": [{"address": "0x402000", "symbol": "g_count", "data_type": {"name": "int"}, "read": True, "write": False}],
        "types": [{"path": "/Example", "name": "Example", "kind": "StructureDataType",
                   "size": 4, "fields": [{"offset": 0, "name": "count", "type": {"name": "int"}}]}],
        "variables": [],
    })


class PromptBuilderTests(unittest.TestCase):
    def test_readable_prompt_preserves_reconstruction_evidence(self):
        from importlib.util import spec_from_file_location, module_from_spec
        spec = spec_from_file_location("build_prompt", SCRIPT)
        module = module_from_spec(spec)
        spec.loader.exec_module(module)

        result = module.render_prompt(example(), "Return C++ only.")
        for phrase in (
            "Return C++ only.", "int FUN_00672cf0(int x)",
            "MOV EAX,ECX", "INC EAX", "INT_ADD", "B0:",
            "unresolved/indirect", "g_count", "+0: int count"
        ):
            self.assertIn(phrase, result)
        self.assertNotIn('"high_pcode":', result)
        self.assertNotIn('"bytes":', result)

    def test_cli_creates_distinct_versions_without_inference(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            src = directory / "context.json"
            src.write_text(json.dumps(example()), encoding="utf-8")
            system = directory / "system.txt"
            system.write_text("Produce source only.", encoding="utf-8")
            out = directory / "output"

            command = [
                sys.executable, str(SCRIPT), str(src),
                "--system-prompt", str(system), "--output-dir", str(out)
            ]
            subprocess.run(command, check=True, capture_output=True, text=True)
            subprocess.run(command, check=True, capture_output=True, text=True)
            self.assertEqual(
                [p.name for p in sorted(out.glob("prompt_v*.md"))],
                ["prompt_v001.md", "prompt_v002.md"],
            )
            self.assertEqual(
                (out / "prompt_v001.md").read_text(),
                (out / "prompt_v002.md").read_text(),
            )


    def test_full_direct_callee_is_included_without_recursion(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            caller = example()
            caller["calls"] = [{
                "site": "0x672cf4",
                "target": "0x672750",
                "instruction": "CALL 0x00672750",
                "callee": {"name": "FUN_00672750",
                           "signature": "undefined FUN_00672750(void)"},
            }]
            src = directory / "caller.json"
            src.write_text(json.dumps(caller), encoding="utf-8")
            callee = example()
            callee["function"]["address"] = "0x672750"
            callee["function"]["name"] = "FUN_00672750"
            callee["function"]["signature"] = "undefined FUN_00672750(void)"
            callee["pseudocode"] = (
                "int *__thiscall FUN_00672750(int *this_, int *begin, int *end) "
                "{ return this_; }"
            )
            callee["assembly"] = [
                {"address": "0x672750", "instruction": "MOV ESI,ECX"},
                {"address": "0x672752", "instruction": "RET 0x8"},
            ]
            callee["high_pcode"] = [{
                "address": "0x672752", "order": 0, "block_index": 0,
                "operation": "RETURN", "inputs": [{"storage": "(register, 0x0, 4)"}],
                "output": None,
            }]
            callee["calls"] = [{"site": "0x672751", "target": "0x401000"}]
            export_dir = directory / "exports"
            export_dir.mkdir()
            (export_dir / "00672750.json").write_text(json.dumps(callee), encoding="utf-8")

            output_dir = directory / "output"
            system = directory / "system.txt"
            system.write_text("Only C++", encoding="utf-8")
            subprocess.run([
                sys.executable, str(SCRIPT), str(src),
                "--system-prompt", str(system),
                "--output-dir", str(output_dir),
                "--callees-dir", str(export_dir),
            ], check=True, capture_output=True, text=True)
            md = (output_dir / "prompt_v001.md").read_text()
            self.assertIn("undefined FUN_00672750(void)", md)
            self.assertIn("int *__thiscall FUN_00672750(", md)
            self.assertIn("MOV ESI,ECX", md)
            self.assertIn("RET 0x8", md)
            self.assertIn("RETURN(", md)
            self.assertIn("0x401000", md)
            self.assertEqual(md.count("### FUN_00672750 at"), 1)
            self.assertNotIn("### Direct call targets without usable exports", md)

    def test_missing_direct_callee_is_labeled_not_invented(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            caller = example()
            caller["calls"] = [{"site": "0x672cf4", "target": "0x672750"}]
            src = directory / "caller.json"
            src.write_text(json.dumps(caller), encoding="utf-8")
            output_dir = directory / "output"
            system = directory / "system.txt"
            system.write_text("Only C++", encoding="utf-8")
            subprocess.run([
                sys.executable, str(SCRIPT), str(src),
                "--system-prompt", str(system),
                "--output-dir", str(output_dir),
                "--callees-dir", str(directory),
            ], check=True, capture_output=True, text=True)
            md = (output_dir / "prompt_v001.md").read_text()
            self.assertIn("0x672750: export not found", md)


if __name__ == "__main__":
    unittest.main()
