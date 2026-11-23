import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import model_client as M


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
