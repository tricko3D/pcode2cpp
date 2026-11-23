"""Offline tests for the C2Scope feedback experiment; no game or model required."""
import io
import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import c2scope_feedback as C
from scripts.probe_body import PREFIX


class C2ScopeFeedbackTests(unittest.TestCase):
    def test_cli_pins_vc9_and_real_c2scope_tools(self):
        cmds = C.c2scope_commands(Path("/c2scope"), Path("/spore/work/test.cpp"),
                                  Path("/case/original.s"), Path("/case"), "test")
        self.assertEqual(cmds["icount"][:3], ["uv", "run", "tools/icount.py"])
        for cmd in cmds.values():
            self.assertIn("--c2", cmd)
            self.assertIn("15.00", cmd)
            self.assertEqual(cmd[-6:], ["--", *C.FLAGS])
            self.assertIn("--func", cmd)
            self.assertIn(C.FUNC, cmd)
        self.assertIn("--allow-local", cmds["icount"])
        self.assertIn("--asm-vs", cmds["schedwant"])

    def test_unresolvable_merge_hook_uses_local_icount_without_merges(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            project = base / "pcode2cpp"
            shim = project / "scripts/c2scope_icount_fallback.py"
            shim.parent.mkdir(parents=True)
            shim.touch()
            case = base / "artifacts"
            case.mkdir()
            c2root = base / "c2scope"
            c2root.mkdir()
            original = case / "retail.s"
            original.write_text("00672cf0 push esi\\n")
            state = {"prepared": "/spore/work/candidate.cpp", "original_asm": str(original)}
            output = [
                subprocess.CompletedProcess([], 1, "", (
                    "no c2 function ?FgDoLateFlowOpts@@YIXPAUtagFUNC@@W4FG_MERGE_ENUM@@@Z\\n"
                )),
                subprocess.CompletedProcess([], 0, "## function: ours 26 orig 24\\n", ""),
                subprocess.CompletedProcess([], 0, "register priority report\\n", ""),
            ]
            calls = []

            def fake_run(args, **kwargs):
                calls.append((args, kwargs))
                if len(calls) == 2:
                    (case / "base.icount.json").write_text(json.dumps({
                        "ours": 26, "orig": 24, "runs": []
                    }))
                return output[len(calls) - 1]

            with patch.object(C, "ROOT", project), patch.object(C.subprocess, "run", fake_run):
                logs = C.run_c2scope(c2root, state, case, "base", sched=False)

            self.assertEqual(len(calls), 3)
            self.assertEqual(calls[0][0][:3], ["uv", "run", "tools/icount.py"])
            self.assertEqual(calls[1][0][:3], ["uv", "run", "python"])
            self.assertEqual(calls[1][0][3], str(shim))
            self.assertIn("--c2", calls[1][0])
            self.assertEqual(calls[1][1]["env"]["C2TRACE_REMOTE"], "0")
            self.assertNotIn("VIRTUAL_ENV", calls[1][1]["env"])
            self.assertTrue(logs["icount"]["fallback_without_merges"])
            self.assertTrue(logs["icount"]["ok"])
            log = (case / "base.icount.log").read_text()
            self.assertIn("no c2 function", log)
            self.assertIn("## function: ours 26 orig 24", log)

    def test_compact_feedback_extracts_actual_icount_findings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "x.icount.json").write_text(json.dumps({
                "ours": 26, "orig": 24,
                "runs": [{"kind": "extra", "line": 9, "src": "param_1[4] = ...",
                          "verdict": "structure", "lever": "prefer member field",
                          "items": [{"ins": "push ebx", "origin": "register allocation"}]}],
                "hints": ["flags match /O2"],
            }))
            (root / "x.regs.log").write_text("register allocation: EBX unused")
            snapshot = {"fingerprint": "size 58, retail 57", "retail_bytes": 57,
                        "candidate_bytes": 58, "retail_instructions": 24,
                        "candidate_instructions": 26, "shape_similarity_heuristic": 0.7}
            data = C.compress_feedback(
                snapshot, {"regs": {"ok": True, "log": str(root / "x.regs.log")}}, root, "x"
            )
            self.assertIn("prefer member field", data)
            self.assertIn("register allocation: EBX unused", data)
            self.assertNotIn("Ghidra High P-code", data)
            self.assertEqual(json.loads(data)["c2scope"]["icount"]["runs"][0]["source_line"], 9)

    def test_prompt_has_c2scope_evidence_but_no_original_ghidra_dump(self):
        messages = C.make_messages("return param_1;", "00672cf0 push esi",
                                   "00672cf0 push ebx", "C2Scope: extra saved register")
        self.assertEqual([m["role"] for m in messages], ["system", "user"])
        self.assertIn("C2Scope: extra saved register", messages[1]["content"])
        self.assertIn("return param_1;", messages[1]["content"])
        self.assertIn("00672cf0 push esi", messages[1]["content"])
        self.assertNotIn("High P-code", str(messages))

    def test_model_streams_one_constrained_json_request_without_tools(self):
        with tempfile.TemporaryDirectory() as temp:
            event = {"choices": [{
                "delta": {"content": '{"body":"return param_1;"}'}, "finish_reason": "stop"
            }]}
            data = io.BytesIO(("data: " + json.dumps(event) + "\n\ndata: [DONE]\n").encode())
            calls = []
            def urlopen(request, timeout):
                calls.append(json.loads(request.data))
                return data
            with patch.object(C, "urlopen", urlopen):
                output = C.stream_model({"model": "local"}, C.make_messages(
                    "return 0;", "", "", "feedback"
                ), Path(temp) / "test.llm.log", 16000)
            self.assertEqual(output, "return param_1;")
            self.assertEqual(len(calls), 1)
            self.assertNotIn("tools", calls[0])
            self.assertEqual(calls[0]["max_tokens"], 16000)
            self.assertEqual(calls[0]["chat_template_kwargs"], {"reasoning_effort": "minimal"})
            self.assertEqual(calls[0]["temperature"], 1.0)

    def test_abort_runaway_reasoning_without_accepting_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            events = [
                {"choices": [{"delta": {"reasoning_content": "thinking again " * 10}}]},
                {"choices": [{"delta": {"reasoning_content": "thinking again " * 10}}]},
            ]
            lines = "".join("data: " + json.dumps(e) + "\n\n" for e in events)
            with patch.object(C, "urlopen", return_value=io.BytesIO(lines.encode("utf-8"))):
                with self.assertRaisesRegex(RuntimeError, "bounded reasoning budget"):
                    C.stream_model({"model": "local"}, C.make_messages(
                        "return param_1;", "", "", "feedback"
                    ), Path(temp) / "repeated.log", 2048, reasoning_limit_chars=100)
            self.assertIn("thinking again", (Path(temp) / "repeated.log").read_text())

    def test_reuses_existing_c2scope_feedback_without_running_trace_again(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = root / "candidate.cpp"
            candidate.write_text(PREFIX + "return param_1;\n}\n")
            prior = root / "previous"
            prior.mkdir()
            (prior / "c2scope_base.icount.json").write_text(json.dumps({
                "ours": 26, "orig": 24, "runs": [{"kind": "extra", "items": []}]
            }))
            old = prior / "candidate_c2scope_001.feedback.json"
            old.write_text(json.dumps({
                "candidate": str(candidate),
                "c2scope_logs": {},
                "messages": [],
            }))
            repo = root / "spore"
            (repo / "tools/contrib").mkdir(parents=True)
            (repo / "tools/contrib/check.py").touch()
            (repo / ".venv/bin").mkdir(parents=True)
            (repo / ".venv/bin/python").touch()
            c2root = root / "c2scope"
            (c2root / "tools").mkdir(parents=True)
            (c2root / "tools/icount.py").touch()
            (root / "config.json").write_text(json.dumps({
                "spore": {"repo_path": str(repo)}, "llm": {}
            }))
            def fake_snapshot(repo, source, case, tag):
                orig = case / "orig.s"
                orig.write_text("00672cf0 push esi\n")
                mine = case / f"{tag}.s"
                mine.write_text("00672cf0 push ebx\n")
                return {"fingerprint": "size 58, retail 57",
                        "retail_bytes": 57, "candidate_bytes": 58,
                        "retail_instructions": 24, "candidate_instructions": 26,
                        "shape_similarity_heuristic": 0.76,
                        "original_asm": str(orig), "candidate_asm": str(mine),
                        "prepared": "fixture"}

            args = type("Args", (), dict(
                candidate=candidate, spore_repo=repo, c2scope_repo=c2root, rounds=1,
                max_tokens=None, inputs=700, proof_timeout=90, dry_run=True,
                no_schedwant=False, resume_feedback=old,
                reasoning_effort="minimal", reasoning_limit_chars=10000
            ))()
            with patch.object(C, "ROOT", root), \
                 patch.object(C, "snapshot", side_effect=fake_snapshot), \
                 patch.object(C, "check_candidate", return_value=type(
                     "Compile", (), {"status": "PASS", "passed": True}
                 )()), \
                 patch.object(C, "run_c2scope", side_effect=AssertionError("trace rerun")):
                result = C.run(args)
            self.assertEqual(result, 0)
            files = list((root / "c2scope_runs/run001").glob("*.feedback.json"))
            self.assertEqual(len(files), 1)
            self.assertIn("size 58", files[0].read_text())

    def test_isolated_inference_keeps_original_and_stops_on_match(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = root / "start.cpp"
            original = PREFIX + "return param_1;\n}\n"
            candidate.write_text(original)
            (root / "config.json").write_text(json.dumps({
                "spore": {"repo_path": str(root / "spore")}, "llm": {"max_tokens": 12345}
            }))
            repo = root / "spore"
            (repo / "tools/contrib").mkdir(parents=True)
            (repo / "tools/contrib/check.py").touch()
            (repo / ".venv/bin").mkdir(parents=True)
            (repo / ".venv/bin/python").touch()
            c2root = root / "c2scope"
            (c2root / "tools").mkdir(parents=True)
            (c2root / "tools/icount.py").touch()
            records = []

            def fake_snapshot(repo, source, case, tag):
                orig = case / "original.s"
                orig.write_text("00672cf0 ret\n")
                mine = case / f"{tag}.s"
                mine.write_text("00672cf0 ret\n")
                records.append(source.name)
                return {
                    "fingerprint": "bytes differ" if source.name == "start.cpp" else "PASS",
                    "retail_bytes": 57, "candidate_bytes": 57, "retail_instructions": 24,
                    "candidate_instructions": 24, "shape_similarity_heuristic": 0.9,
                    "original_asm": str(orig), "candidate_asm": str(mine), "prepared": "fixture"
                }

            args = type("Args", (), dict(
                candidate=candidate, spore_repo=repo, c2scope_repo=c2root, rounds=3,
                max_tokens=None, inputs=700, proof_timeout=90, dry_run=False,
                no_schedwant=False, resume_feedback=None,
                reasoning_effort="minimal", reasoning_limit_chars=10000
            ))()
            with patch.object(C, "ROOT", root), \
                 patch.object(C, "snapshot", side_effect=fake_snapshot), \
                 patch.object(C, "check_candidate", return_value=type(
                     "Compile", (), {"status": "PASS", "passed": True}
                 )()), \
                 patch.object(C, "run_c2scope", side_effect=lambda c2, state, case, tag, **kwargs: (
                     (case / f"{tag}.icount.json").write_text(json.dumps({
                         "ours": 26, "orig": 24, "runs": []
                     })) and {}
                 )), \
                 patch.object(C, "stream_model", return_value="return param_1;\nparam_1[0] = 1;"), \
                 patch.object(C, "formal_test", return_value="MATCH"):
                result = C.run(args)
            self.assertEqual(result, 0)
            self.assertEqual(records, ["start.cpp", "start_c2scope_001.cpp"])
            self.assertEqual(candidate.read_text(), original)
            run_dir = root / "c2scope_runs/run001"
            self.assertTrue((run_dir / "start_c2scope_001.cpp").is_file())
            self.assertTrue((run_dir / "start_c2scope_summary.json").is_file())
            self.assertFalse((run_dir / "start_c2scope_002.cpp").exists())


if __name__ == "__main__":
    unittest.main()
