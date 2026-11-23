"""Offline tests for the resumable VC9 beam search; no Spore/C2Scope required."""
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from scripts import auto_match as A


class AutoMatchTests(unittest.TestCase):
    def test_field_dependency_operator_recreates_discovered_rewrite(self):
        source = (
            'param_1[4] = (int)(param_1 + 5);\n'
            'param_1[2] = (int)(param_1 + 0x15);\n'
            'param_1[1] = (int)(param_1 + 5);\n'
        )
        variants = list(A.field_dependency_mutations(source))
        self.assertTrue(variants)
        self.assertTrue(any('param_1[2] = (int)((unsigned int)param_1[4] + 0x40u);' in text
                            for _, text in variants))
        self.assertEqual(source.count('param_1[2]'), 1)
        self.assertEqual(list(A.field_dependency_mutations('return param_1;')), [])

    def test_sweep_parser_reads_scores_and_real_combination_paths(self):
        log = '''3 variables, 9 statements, 278 variants (wrap 61)
baseline: 26 instructions, rdiff 12, bdiff 33, regdiff 26
278 measured, 0 failed to compile
   id   family shape regs rdiff bdiff regdiff   rewrite
  v0024 wrap       6    6     8*    29     22    hs_bind(param_1) @33
  v0084 alias      6    6     9*    31     24    ref param_1
  v0024+v0084      shape 6 regs 6  rdiff 7 bdiff 28 regdiff 20
variants: /tmp/c2scope/work/variant-abc@15.00/v<id>/v<id>.cpp
'''
        baseline, variants, measured = A.parse_sweep(log)
        self.assertEqual(baseline, (12, 33))
        self.assertEqual(measured, 278)
        self.assertEqual([v[0] for v in variants], ['v0024+v0084', 'v0024', 'v0084'])
        self.assertEqual(str(variants[0][3]),
                         '/tmp/c2scope/work/variant-abc@15.00/c_0024_0084/c_0024_0084.cpp')

    def test_resume_reuses_sources_and_budget_without_duplicate_insertions(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            store = A.Store(root)
            original = 'int f() { return 1; }'
            key = store.add(original, None, 'seed', 0, None, None)
            store.add(original, None, 'seed', 0, None, None)
            store.debit(41)
            store.update(key, proof='EQUIVALENT', rdiff=2, bdiff=6)
            store.db.close()
            resumed = A.Store(root)
            self.assertEqual(len(resumed.all()), 1)
            self.assertEqual(resumed.count(), 41)
            self.assertEqual(resumed.best_proven()['id'], key)
            self.assertEqual(Path(resumed.row(key)['path']).read_text(), original)

    def test_frontier_reserves_slot_for_unscored_field_dependency(self):
        with tempfile.TemporaryDirectory() as folder:
            s = A.Store(Path(folder))
            seed = s.add('seed', None, 'seed', 0, 2, 6)
            s.update(seed, expanded=1)
            for i in range(10):
                s.add('candidate%d' % i, seed, 'rwsweep:v%04d' % i, 1, 1, i + 3)
            special = s.add('special', seed, 'field:param_1[2]<-4', 1, 10, 30)
            self.assertIn(special, [x['id'] for x in s.eligible(4, 2)])

    def test_duplicate_machine_reuses_formal_verdict_and_skips_proof(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            work = A.Store(root)
            original = work.add('a', None, 'seed', 0, 2, 6)
            other = work.add('b', original, 'rwsweep:v0001', 1, 1, 4)
            state = {'machine_sha256': 'abc', 'fingerprint': 'bytes differ',
                     'prepared': str(root / 'in_spore.cpp'), 'candidate_bytes': 57,
                     'callee_symbol_valid': True}
            work.update(original, machine='abc', snapshot=json.dumps(state),
                        proof='EQUIVALENT', empirical='PASS', status='EQUIVALENT')
            fake = types.SimpleNamespace(store=work, repo=root, a=types.SimpleNamespace(
                inputs=700, proof_timeout=90), remaining=lambda: 100)
            with patch.object(A, 'snapshot_prepared', return_value=state), \
                 patch.object(A, 'copy_prepared', side_effect=AssertionError('unexpected')), \
                 patch.object(A, 'proof_worker', side_effect=AssertionError('unexpected')):
                self.assertFalse(A.Engine.evaluate(fake, other, do_unicorn=True, do_proof=True))
            self.assertEqual(work.row(other)['status'], 'DUPLICATE_MACHINE')
            self.assertEqual(work.row(other)['proof'], 'EQUIVALENT')
            self.assertEqual(work.count(), 1)

    def test_engine_searches_across_generations_without_live_tools(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            seed = root / 'seed.cpp'
            seed.write_text('''struct InklingCandidate_s00672cf0 {};
int* InklingCandidate_s00672cf0::FUN_00672cf0(int* param_2) {
param_1[4] = (int)(param_1 + 5);
param_1[2] = (int)(param_1 + 0x15);
return param_1;
}
''')
            repo = root / 'spore'
            (repo / 'tools/difftest').mkdir(parents=True)
            (repo / 'tools/difftest/equiv.py').touch()
            (repo / '.venv/bin').mkdir(parents=True)
            (repo / '.venv/bin/python').touch()
            c2root = root / 'c2scope'
            (c2root / 'tools').mkdir(parents=True)
            (c2root / 'tools/rwsweep.py').touch()
            opts = A.build_parser().parse_args([
                '--seed', str(seed), '--spore-repo', str(repo),
                '--c2scope-repo', str(c2root), '--work-dir', str(root / 'state'),
                '--max-generations', '2', '--max-compiles', '30',
                '--per-parent-limit', '3', '--verify-combos', '0',
                '--beam-width', '1', '--evaluate-top', '2', '--formal-top', '1',
                '--unicorn-top', '1',
            ])
            calls = []
            def fake_snap(repo, src, case, tag):
                calls.append(src.read_text())
                (case / 'original.s').write_text('00672cf0 ret\n')
                return {'machine_sha256': A.digest(src.read_text()),
                        'fingerprint': 'bytes differ',
                        'prepared': str(src), 'candidate_bytes': 57,
                        'callee_symbol_valid': True}
            def fake_sweep(self, row):
                self.store.update(row['id'], expanded=1, rdiff=12, bdiff=33)
                return []
            with patch.object(A, 'snapshot_prepared', side_effect=fake_snap), \
                 patch.object(A.Engine, 'sweep', fake_sweep), \
                 patch.object(A.C, 'differential_test', return_value={'verdict': 'PASS'}), \
                 patch.object(A, 'proof_worker', return_value='EQUIVALENT'):
                eng = A.Engine(opts)
                self.assertEqual(eng.run(), 0)
            self.assertTrue(any('0x40u' in c for c in calls))
            self.assertTrue((root / 'state/summary.json').exists())
            self.assertEqual(A.Store(root / 'state').getmeta('estimated_compiles'), 2)

    def test_proved_candidate_is_not_replaced_by_unproven_lower_diff(self):
        with tempfile.TemporaryDirectory() as folder:
            s = A.Store(Path(folder))
            proven = s.add('v0037', None, 'seed', 0, 1, 4)
            s.update(proven, proof='EQUIVALENT', status='EQUIVALENT')
            unproven = s.add('another', proven, 'rwsweep:v1', 1, 0, 1)
            s.update(unproven, proof='REFUTED', status='REFUTED')
            self.assertEqual(s.best_proven()['id'], proven)


if __name__ == '__main__':
    unittest.main()
