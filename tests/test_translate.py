import json
import unittest
from unittest.mock import patch

from pcode2cpp.translate import build_messages, translate
from tests.test_context import sample


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps({
            "choices": [{"message": {"content": "int Test(int x) { return x + 1; }"}, "finish_reason": "stop"}],
            "usage": {"total_tokens": 83},
        }).encode()


class TranslateTests(unittest.TestCase):
    def test_prompt_contains_pcode_and_context(self):
        messages = build_messages(sample())
        self.assertIn("High P-code", messages[0]["content"])
        self.assertIn("INT_ADD", messages[1]["content"])
        self.assertIn("0x672cf0", messages[1]["content"])

    @patch("pcode2cpp.translate.request.urlopen", return_value=FakeResponse())
    def test_single_local_inference_no_tools(self, urlopen):
        code, meta = translate(sample(), {"url": "http://127.0.0.1:8080/v1/chat/completions"})
        self.assertTrue(code.startswith("int Test"))
        self.assertEqual(meta["usage"]["total_tokens"], 83)
        self.assertEqual(urlopen.call_count, 1)
        payload = json.loads(urlopen.call_args.args[0].data)
        self.assertNotIn("tools", payload)
        self.assertEqual(payload["temperature"], 0)
        self.assertIn("INT_ADD", payload["messages"][1]["content"])

    def test_remote_inference_blocked(self):
        with self.assertRaisesRegex(ValueError, "local loopback"):
            translate(sample(), {"url": "https://api.openrouter.ai/v1/chat/completions"})


if __name__ == "__main__":
    unittest.main()
