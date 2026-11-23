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


if __name__ == "__main__":
    unittest.main()
