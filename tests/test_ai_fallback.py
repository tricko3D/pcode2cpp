import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from scripts import ai_fallback as I
from scripts import auto_match as A

SOURCE = '''struct InklingCandidate_s00672cf0 {
    int* __thiscall FUN_00672cf0(int* param_2);
};
int* InklingCandidate_s00672cf0::FUN_00672cf0(int* param_2) {
    int* param_1 = (int*)this;
    param_1[2] = (int)(param_1 + 0x15);
    return param_1;
}
'''

class AiTests(unittest.TestCase):
    def test_only_one_function_body_substitution(self):
        out=I.apply_edit(SOURCE, {'find':'param_1[2] = (int)(param_1 + 0x15);',
                                  'replace':'param_1[2] = (int)((unsigned int)param_1[4] + 0x40u);'})
        self.assertIn('0x40u',out)
        self.assertEqual(out.count(I.FUNCTION),1)
        with self.assertRaisesRegex(ValueError,'exactly once'):
            I.apply_edit(SOURCE,{'find':'param_1[99]', 'replace':'something'})
        with self.assertRaisesRegex(ValueError,'forbidden'):
            I.apply_edit(SOURCE,{'find':'return param_1;', 'replace':'__asm { nop }'})
        with self.assertRaisesRegex(ValueError,'unbalance function braces'):
            I.apply_edit(SOURCE,{'find':'return param_1;', 'replace':'return param_1; }'})

    def test_prompt_targets_discrepancy_not_ghidra_dump(self):
        msgs=I.build_messages(SOURCE,'00672cf0 push edi\n','00672cf0 mov [esi+8], ecx\n',
                              (1,4),[],6)
        self.assertIn('push edi',msgs[1]['content'])
        self.assertIn('bdiff',msgs[1]['content'])
        self.assertNotIn('High P-code',msgs[1]['content'])

    def test_ai_round_is_durable_and_not_requeried(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            store=A.Store(root)
            seed=store.add(SOURCE,None,'seed',0,1,4)
            retail=root/'retail.s'; candidate=root/'compiled.s'
            retail.write_text('retail push edi\n');candidate.write_text('mine push edi\n')
            store.update(seed,snapshot=json.dumps({'original_asm':str(retail),'candidate_asm':str(candidate)}),
                         proof='EQUIVALENT', status='EQUIVALENT')
            e=SimpleNamespace(store=store)
            profile={'name':'inkling-small','model':'local','url':'http://127.0.0.1:8080/v1/chat/completions'}
            answer={'edits':[{'find':'param_1[2] = (int)(param_1 + 0x15);',
                              'replace':'param_1[2] = (int)((unsigned int)param_1[4] + 0x40u);'}]}
            with patch.object(I,'chat_json',return_value=(answer,{'usage':{}})) as client:
                first=I.produce_round(e,profile,1,6)
                second=I.produce_round(e,profile,1,6)
            self.assertEqual(first,second)
            self.assertEqual(client.call_count,1)
            self.assertEqual(len(first),1)
            self.assertTrue((root/'logs').exists())

    def test_mechanical_stage_runs_before_ai_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            store=A.Store(Path(folder))
            seed=store.add('base',None,'seed',0,1,4)
            store.update(seed,snapshot='{}',status='EQUIVALENT',proof='EQUIVALENT')
            events=[]
            fake=SimpleNamespace(store=store,a=SimpleNamespace(max_compiles=50,min_sweep_budget=24),
                run=lambda: events.append('mechanical'), summary=lambda: None)
            with patch.object(I,'produce_round',side_effect=lambda *args: events.append('ai') or []):
                out=I.run_with_fallback(fake, {'name':'mini','model':'local','url':'http://127.0.0.1:8080/v1/chat/completions'},
                    rounds=1,patches=2,compiles_per_round=10)
            self.assertEqual(events,['mechanical','ai'])
            self.assertEqual(out,0)
