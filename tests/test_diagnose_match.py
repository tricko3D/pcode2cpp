"""Offline tests for read-only diagnostic CLI. No real VC9, model or API."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from scripts import diagnose_match as D


def fixture(folder):
    db = sqlite3.connect(folder / "search.sqlite3")
    db.execute("""CREATE TABLE candidates (
        id TEXT PRIMARY KEY, path TEXT NOT NULL, parent TEXT, origin TEXT NOT NULL,
        generation INTEGER NOT NULL, rdiff INTEGER, bdiff INTEGER,
        machine TEXT, fingerprint TEXT, empirical TEXT, proof TEXT,
        status TEXT NOT NULL DEFAULT 'NEW', expanded INTEGER NOT NULL DEFAULT 0,
        snapshot TEXT, note TEXT DEFAULT '')""")
    retail, mine = folder / "retail.s", folder / "compiled.s"
    retail.write_text("push edi\nmov edi,[esp + 0xc]\nmov [esi + 8],ecx\n")
    mine.write_text("mov [esi + 8],ecx\npush edi\nmov edi,[esp + 0xc]\n")
    for ident, source, rdiff, bdiff, proof in [
        ("proven", "int f(){return 1;}", 1, 4, "EQUIVALENT"),
        ("refuted", "int f(){return 2;}", 0, 0, "REFUTED"),
    ]:
        src = folder / (ident + ".cpp")
        src.write_text(source)
        db.execute("""INSERT INTO candidates
            (id,path,origin,generation,rdiff,bdiff,proof,status,snapshot)
            VALUES (?,?,'seed',0,?,?,?,?,
                    ?)""",
            (ident, str(src), rdiff, bdiff, proof, proof,
             json.dumps({"original_asm":str(retail), "candidate_asm":str(mine),
                         "fingerprint":"bytes differ", "retail_bytes":57,
                         "candidate_bytes":57, "callee_symbol_valid":True})))
    db.commit()
    db.close()


class DiagnosisTests(unittest.TestCase):
    def test_locate_requires_database(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaisesRegex(ValueError, "search.sqlite3"):
                D.locate_state(Path(t))

    def test_strongest_proven_beats_closer_refuted(self):
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            fixture(folder)
            search = D.ReadOnlyCandidates(folder)
            with patch.object(D, "select_catalog", return_value="prologue"):
                evidence = D.assemble_evidence(search)
            search.db.close()
            self.assertEqual(evidence["best_candidate_source"], "int f(){return 1;}")
            self.assertEqual(evidence["proof_verdict"], "EQUIVALENT")
            self.assertEqual((evidence["rdiff"], evidence["bdiff"]), (1, 4))
            self.assertIn("+mov [esi + 8],ecx", evidence["assembly_diff"])

    def test_catalog_shortlist_is_smaller_than_full(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "cat.md"
            path.write_text("## Highest-priority shortlist for the current 0x00672CF0 near-match\n"
                            "important\n## Full catalog\nlong catalog\n")
            with patch.object(D, "CATALOG", path):
                self.assertEqual(D.select_catalog(False), "important")
                self.assertIn("long catalog", D.select_catalog(True))

    def test_diagnosis_answer_forbids_patch_keys(self):
        answer = {"observed_difference":"one move",
                  "most_likely_cause":"prologue placement",
                  "alternative_causes":[],
                  "best_next_diagnostic":"trace prologue phase",
                  "techniques_considered":["prologue","liveness"],
                  "confidence":"medium"}
        self.assertEqual(D.validate_answer(answer), answer)
        self.assertIn("prologue placement", D.render(answer))
        with self.assertRaisesRegex(ValueError, "unexpected"):
            D.validate_answer(dict(answer, patch="edited C++"))
        with self.assertRaisesRegex(ValueError, "confidence"):
            D.validate_answer(dict(answer, confidence="certain"))

    def test_dry_run_does_not_call_model_or_write_database(self):
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            fixture(folder)
            original_mtime = (folder / "search.sqlite3").stat().st_mtime_ns
            with patch.object(D, "select_catalog", return_value="prologue"), \
                 patch.object(D, "chat_json", side_effect=AssertionError("no inference")):
                self.assertEqual(D.main(["--work-dir", str(folder), "--dry-run"]), 0)
            self.assertEqual((folder / "search.sqlite3").stat().st_mtime_ns, original_mtime)
            self.assertEqual(len(list((folder / "diagnoses").glob("*/request.json"))), 1)
            self.assertFalse(list((folder / "diagnoses").glob("*/diagnosis.md")))


if __name__ == "__main__":
    unittest.main()
