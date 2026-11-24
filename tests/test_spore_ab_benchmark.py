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

    def test_three_independent_arms_are_recorded(self):
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
                results = B.read(base / "comparison.json")["arms"]
                self.assertEqual(set(results), {"pipeline", "isolated", "agent"})


if __name__ == "__main__":
    unittest.main()
