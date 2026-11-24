import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import model_client as M
from scripts import codex_chat as C
from types import SimpleNamespace


class Response:
    def __init__(self, obj): self.obj=obj
    def __enter__(self): return self
    def __exit__(self, *args): return None
    def read(self): return json.dumps(self.obj).encode()


class ModelTests(unittest.TestCase):
    def test_profile_remote_requires_consent_and_https(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'profiles.json'
            p.write_text(json.dumps({'profiles': {'ds': {'url':'https://api.deepseek.com/chat/completions', 'model':'deepseek-flash', 'api_key_env':'TEST_KEY'}}}))
            with self.assertRaisesRegex(ValueError,'allow-remote'):
                M.load_profile(p,'ds')
            self.assertEqual(M.load_profile(p,'ds',allow_remote=True)['model'],'deepseek-flash')
            p.write_text(json.dumps({'profiles': {'ds': {'url':'http://api.deepseek.com/chat/completions', 'model':'deepseek-flash', 'api_key_env':'TEST_KEY'}}}))
            with self.assertRaisesRegex(ValueError,'HTTPS'):
                M.load_profile(p,'ds',allow_remote=True)

    def test_local_model_json_without_tools(self):
        profile={'url':'http://127.0.0.1:8080/v1/chat/completions','model':'local'}
        calls=[]
        def fake(req,timeout):
            payload=json.loads(req.data)
            calls.append(payload)
            return Response({'choices':[{'message': {'content':'```json\n{"edits": []}\n```'},'finish_reason':'stop'}],'usage':{'total_tokens':42}})
        value,meta=M.chat_json(profile,[{'role':'user','content':'test'}],call=fake)
        self.assertEqual(value,{'edits':[]})
        self.assertEqual(meta['usage']['total_tokens'],42)
        self.assertNotIn('tools',calls[0])

    def test_authentication_is_env_only_and_not_in_request_body(self):
        profile={'url':'https://api.deepseek.com/chat/completions','model':'deepseek-flash','api_key_env':'TEST_KEY'}
        def fake(req,timeout):
            self.assertEqual(req.get_header('Authorization'),'Bearer private-test')
            self.assertNotIn('private-test',req.data.decode())
            return Response({'choices':[{'message':{'content':'{"edits":[]}'},'finish_reason':'stop'}]})
        with patch.dict(os.environ,{'TEST_KEY':'private-test'}):
            M.chat_json(profile,[{'role':'user','content':'test'}],call=fake)

    def test_rejects_truncated_model_response(self):
        def fake(req,timeout):
            return Response({'choices':[{'message': {'content':'{"edits":[]}'},'finish_reason':'length'}]})
        with self.assertRaisesRegex(M.ModelError,'Incomplete'):
            M.chat_json({'url':'http://127.0.0.1:8080/v1/chat/completions','model':'local'},
                        [{'role':'user','content':'test'}],call=fake)

    def test_codex_cli_profile_and_json_model_transport(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "profiles.json"
            path.write_text(json.dumps({"profiles": {
                "codex-plus": {"provider": "codex_cli", "model": "default"}
            }}))
            profile = M.load_profile(path, "codex-plus")
            self.assertEqual(profile["url"], "codex-cli://chatgpt")
            # Codex model uses ChatGPT login, not --allow-remote or API key.
            self.assertEqual(profile["model"], "default")

        events = [
            {"type": "item.completed", "item": {
                "type": "agent_message", "text": '{"body":"return param_1;"}'}},
            {"type": "turn.completed", "usage": {"input_tokens": 10, "output_tokens": 12}},
        ]
        fake = SimpleNamespace(returncode=0, stderr="",
                               stdout="\n".join(json.dumps(e) for e in events))
        with patch.object(C.shutil, "which", return_value="/usr/bin/codex"), \
             patch.object(C.subprocess, "run", return_value=fake) as run:
            value, meta = M.chat_json(profile, [
                {"role": "system", "content": "Reconstruct C++"},
                {"role": "user", "content": "retail bytes"},
            ])
        self.assertEqual(value["body"], "return param_1;")
        self.assertEqual(meta["provider"], "codex_cli")
        argv = run.call_args.args[0]
        self.assertIn("--output-schema", argv)
        self.assertNotIn("--model", argv)  # user-configured Codex model
        self.assertEqual(run.call_args.kwargs["cwd"].startswith("/tmp/"), True)

    def test_codex_fallback_accepts_edits_and_rejects_tools(self):
        profile = {"provider": "codex_cli", "model": "default"}
        edits = [
            {"type": "item.completed", "item": {
                "type": "agent_message", "text": '{"edits":[]}'}},
            {"type": "turn.completed", "usage": {}},
        ]
        good = SimpleNamespace(returncode=0, stderr="",
                               stdout="\n".join(json.dumps(e) for e in edits))
        prompt = [
            {"role": "system", "content": "You are proposing C++ source mutations for VC9."},
            {"role": "user", "content": "source and assembly"},
        ]
        with patch.object(C.shutil, "which", return_value="/usr/bin/codex"), \
             patch.object(C.subprocess, "run", return_value=good):
            result, _ = M.chat_json(profile, prompt)
            self.assertEqual(result["edits"], [])

        tool = {"type": "item.started", "item": {"type": "command_execution"}}
        bad = SimpleNamespace(returncode=0, stderr="",
                              stdout="\n".join([json.dumps(tool)] + [json.dumps(e) for e in edits]))
        with patch.object(C.shutil, "which", return_value="/usr/bin/codex"), \
             patch.object(C.subprocess, "run", return_value=bad):
            with self.assertRaisesRegex(M.ModelError, "used tools"):
                M.chat_json(profile, prompt)
