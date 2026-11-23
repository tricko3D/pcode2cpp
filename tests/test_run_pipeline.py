import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from scripts import run_pipeline as P

class PipelineTests(unittest.TestCase):
    def test_cli_seed_reuses_existing_candidate_skipping_ghidra(self):
        with tempfile.TemporaryDirectory() as d:
            seed=Path(d)/'input.cpp'; seed.write_text('int fake() {}')
            argv=['--seed',str(seed),'--fallback-model','inkling-small',
                  '--models',str(Path(d)/'models.json')]
            fake=SimpleNamespace()
            profile={'name':'inkling-small','url':'http://127.0.0.1:8080/v1/chat/completions','model':'local'}
            with patch.object(P,'load_profile',return_value=profile), \
                 patch.object(P.A,'Engine',return_value=fake), \
                 patch.object(P.AI,'run_with_fallback',return_value=0) as run, \
                 patch.object(P,'reconstruct',side_effect=AssertionError('no ghidra')):
                self.assertEqual(P.main(argv),0)
            self.assertEqual(run.call_count,1)

    def test_initial_messages_uses_full_context_and_body_contract(self):
        context={'pseudocode':'return 99;', 'function':{'address':'0x00672cf0'}}
        with patch.object(P.BP,'render_prompt',return_value='FULL HIGH PCODE EVIDENCE'):
            msgs=P.initial_messages(context,{},[])
        self.assertIn('FULL HIGH PCODE EVIDENCE',msgs[1]['content'])
        self.assertIn('single string key "body"',msgs[0]['content'])
        self.assertIn(P.PREFIX,msgs[1]['content'])

    def test_initial_model_stays_separate_from_mechanical_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            profile={'name':'inkling-small','url':'http://127.0.0.1:8080/v1/chat/completions','model':'local'}
            context={'function':{'address':'0x00672cf0'},'pseudocode':'return param_1;'}
            args=SimpleNamespace(address=0x00672cf0,run_dir=root,context=root/'ctx.json',
                                 config=root/'config.json',callees_dir=root,repairs=0)
            (root/'ctx.json').write_text(json.dumps(context))
            with patch('pcode2cpp.context.load_context',return_value=context), \
                 patch.object(P.BP,'read_direct_callees',return_value=({},[])), \
                 patch.object(P,'initial_messages',return_value=[{'role':'user','content':'test'}]), \
                 patch.object(P,'chat_json',return_value=({'body':'return param_1;'},{})), \
                 patch.object(P.Check,'check_candidate',return_value=SimpleNamespace(passed=True)):
                result=P.reconstruct(args,profile)
                again=P.reconstruct(args,profile)
            self.assertEqual(result,again)
            self.assertIn('return param_1;',result.read_text())
            self.assertTrue((root/'initial_response.json').is_file())
