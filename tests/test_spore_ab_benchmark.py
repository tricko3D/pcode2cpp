"""Offline checks for the generalized Spore A/B harness.

No real Ghidra, Wine, remote Codex or retail game image is used here.
"""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from scripts import spore_ab_benchmark as B
from scripts import select_large_spore as S


class BenchmarkTests(unittest.TestCase):
    def test_size_range_and_claim_checks_are_part_of_selection(self):
        self.assertIn("T.never_tried", S.SELECTOR)
        self.assertIn("T.marked()", S.SELECTOR)
        self.assertIn("T.shape_only()", S.SELECTOR)
        self.assertIn("T.equivalent()", S.SELECTOR)
        self.assertIn("T.claims()", S.SELECTOR)
        self.assertIn("T.stale", S.SELECTOR)
        self.assertIn("T.new_source_path", S.SELECTOR)

    def test_single_run_action_is_supported(self):
        # The runner must execute the shared pipeline before its refinements.
        import inspect
        body = inspect.getsource(B.main)
        self.assertIn('if args.action == "run":', body)
        self.assertLess(body.find("pipeline(args)"), body.find("isolated(args)"))
        self.assertLess(body.find("isolated(args)"), body.find("agent(args)"))

    def test_rate_change_same_reset_and_reset_during_run(self):
        before = {"limits": {
            "primary": {"resets_at": 10, "window_minutes": 300, "used_percent": 4.0},
            "secondary": {"resets_at": 20, "window_minutes": 10080, "used_percent": 1.0}}}
        after = {"limits": {
            "primary": {"resets_at": 10, "window_minutes": 300, "used_percent": 5.0},
            "secondary": {"resets_at": 21, "window_minutes": 10080, "used_percent": 0.0}}}
        report = B.allowance(before, after)
        self.assertEqual(report["primary"]["estimated_percentage_point_change"], 1.0)
        self.assertIn("unavailable", report["secondary"])

    def test_verifier_only_counts_exact_match_not_equivalence(self):
        cases = [
            ("NO MATCH  0x0088abcd  ?some@@symbol", False),
            ("EQUIVALENT 0x0088abcd", False),
            ("MATCH  0x0088abcd  ?some@@symbol", True),
            ("COMPILE FAILED", False),
        ]
        with tempfile.TemporaryDirectory() as temp:
            checkout = Path(temp)
            (checkout / ".venv/bin").mkdir(parents=True)
            for i, (stdout, expected) in enumerate(cases):
                response = SimpleNamespace(returncode=0 if expected else 1,
                                           stdout=stdout, stderr="")
                with patch.object(B, "command", return_value=response):
                    got = B.verify(checkout, "0x0088abcd", checkout / f"log{i}.txt")
                self.assertEqual(got["match"], expected)

    def test_shared_pipeline_and_two_refinements_are_recorded(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(B, "BASE", Path(temp)):
                address = "0x0088abcd"
                base = B.experiment_dir(address)
                B.save(base / "experiment.json", {
                    "target": {"address": address, "retail_bytes": 1200},
                    "baseline_commit": "deadbeef",
                    "context_sha256": "aa",
                    "evidence_sha256": "bb",
                })
                B.report(SimpleNamespace(address=address))
                results = B.read(base / "comparison.json")
                self.assertIn("common_pipeline", results)
                self.assertEqual(set(results["refinements"]), {"isolated", "agent"})
                self.assertFalse(results["comparison_valid_identical_starting_candidates"])


    def test_both_refinements_receive_exact_same_pipeline_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            address = "0x0088abcd"
            relative = "match/slices/s0088abcd/s0088abcd.cpp"
            payload = b"// @ 0x0088abcd\nint f() { return 42; }\n"
            handoff = base / "pipeline/handoff.cpp"
            handoff.parent.mkdir(parents=True)
            handoff.write_bytes(payload)
            digest = B.sha(payload)
            B.save(base / "pipeline/result.json", {
                "handoff_sha256": digest,
                "handoff_verification": {"feedback": "NO MATCH: bytes differ"},
            })
            meta = {"target": {"address": address, "retail_bytes": 1200},
                    "target_source": relative}
            hashes = []
            for arm in ("isolated", "agent"):
                source = base / arm / "spore" / relative
                source.parent.mkdir(parents=True)
                source.write_text("// @ 0x0088abcd\n// No implementation yet.\n")
                result, prompt = B.handoff_to_refinement(base, meta, arm)
                hashes.append(result)
                self.assertEqual(source.read_bytes(), payload)
                self.assertIn("NO MATCH", prompt)
            self.assertEqual(hashes, [digest, digest])
            with self.assertRaisesRegex(RuntimeError, "not pristine"):
                B.handoff_to_refinement(base, meta, "isolated")


if __name__ == "__main__":
    unittest.main()
