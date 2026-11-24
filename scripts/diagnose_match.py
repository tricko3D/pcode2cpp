#!/usr/bin/env python3
"""Explain why the strongest formally verified VC9 source is not byte-exact.

Diagnosis only: reads auto_match SQLite read-only, never edits candidate C++
or search state, and never asks the model for source patches or tools.
"""
import argparse
from datetime import datetime, timezone
import difflib
import json
from pathlib import Path
import re
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from .model_client import chat_json, load_profile
except ImportError:
    from model_client import chat_json, load_profile

PROMPT = ROOT / "prompts/byte_match_diagnosis.md"
CATALOG = ROOT / "docs/byte-match-techniques.md"


class ReadOnlyCandidates:
    """Read existing search state without changing tables or opening a write DB."""
    def __init__(self, folder: Path):
        uri = (folder / "search.sqlite3").resolve().as_uri() + "?mode=ro"
        self.db = sqlite3.connect(uri, uri=True)
        self.db.row_factory = sqlite3.Row

    def all(self):
        return self.db.execute("SELECT * FROM candidates").fetchall()

    def best_proven(self):
        candidates = [r for r in self.all() if r["proof"] in ("MATCH", "EQUIVALENT")]
        score = lambda r: (r["rdiff"] if r["rdiff"] is not None else 10000,
                           r["bdiff"] if r["bdiff"] is not None else 10000)
        return min(candidates, key=score) if candidates else None


def locate_state(folder: Path | None) -> Path:
    if folder is not None:
        result = folder.expanduser().resolve()
        if not (result / "search.sqlite3").is_file():
            raise ValueError("No search.sqlite3 in " + str(result))
        return result
    base = ROOT / "cases/00672cf0/auto_match"
    matches = sorted(p.parent for p in base.glob("*/search.sqlite3"))
    if len(matches) != 1:
        raise ValueError("Found %d search databases; specify --work-dir" % len(matches))
    return matches[0]


def select_catalog(full: bool) -> str:
    contents = CATALOG.read_text(encoding="utf-8")
    if full:
        return contents
    header = "## Highest-priority shortlist for the current 0x00672CF0 near-match"
    footer = "\n## Full catalog"
    if header not in contents or footer not in contents:
        raise ValueError("Technique catalog missing shortlist/full sections")
    return contents.split(header, 1)[1].split(footer, 1)[0].strip()


def assemble_evidence(search: ReadOnlyCandidates, full_catalog=False) -> dict:
    row = search.best_proven()
    if row is None:
        raise ValueError("No formally EQUIVALENT or MATCH candidate in the database")
    if not row["snapshot"]:
        raise ValueError("Proven candidate lacks VC9 snapshot")
    snapshot = json.loads(row["snapshot"])
    source = Path(row["path"]).read_text(encoding="utf-8")
    retail = Path(snapshot["original_asm"]).read_text(encoding="utf-8")
    compiled = Path(snapshot["candidate_asm"]).read_text(encoding="utf-8")
    asm_diff = "".join(difflib.unified_diff(
        retail.splitlines(keepends=True),
        compiled.splitlines(keepends=True),
        fromfile="retail", tofile="compiled_candidate",
    ))
    seen = set()
    previous = []
    events = sorted((r for r in search.all() if r["id"] != row["id"] and r["snapshot"]),
                    key=lambda r: (r["rdiff"] if r["rdiff"] is not None else 10000,
                                   r["bdiff"] if r["bdiff"] is not None else 10000))
    for event in events:
        family = event["origin"].split(":", 1)[0]
        key = (family, event["rdiff"], event["bdiff"], event["proof"], event["status"])
        if key in seen:
            continue
        seen.add(key)
        previous.append({
            "mutation_family": family, "rdiff": event["rdiff"], "bdiff": event["bdiff"],
            "proof": event["proof"], "status": event["status"]
        })
        if len(previous) >= 12:
            break
    return {
        "function": "Spore retail x86 0x00672cf0",
        "toolchain": "VC9 15.00.30729.1, /O2 /MD /Gy /EHsc /TP",
        "best_candidate_path": str(row["path"]),
        "best_candidate_source": source,
        "retail_assembly": retail,
        "compiled_assembly": compiled,
        "assembly_diff": asm_diff,
        "rdiff": row["rdiff"], "bdiff": row["bdiff"],
        "fingerprint": snapshot.get("fingerprint"),
        "proof_verdict": row["proof"],
        "retail_bytes": snapshot.get("retail_bytes"),
        "compiled_bytes": snapshot.get("candidate_bytes"),
        "callee_symbol_valid": snapshot.get("callee_symbol_valid"),
        "callee_target_assumption": snapshot.get("callee_target"),
        "prior_experiments": previous,
        "diagnostic_techniques": select_catalog(full_catalog),
        "task": "Explain root cause hypotheses only. Do not write or change C++.",
    }


def validate_answer(answer):
    required = {"observed_difference", "most_likely_cause", "alternative_causes",
                "best_next_diagnostic", "techniques_considered", "confidence"}
    if set(answer) != required:
        raise ValueError("Diagnosis answer has unexpected or missing JSON keys")
    for key in ("observed_difference", "most_likely_cause", "best_next_diagnostic"):
        if not isinstance(answer[key], str) or not answer[key].strip():
            raise ValueError("Missing diagnosis field " + key)
    if answer["confidence"] not in ("low", "medium", "high"):
        raise ValueError("Invalid confidence")
    if (not isinstance(answer["alternative_causes"], list)
            or len(answer["alternative_causes"]) > 2
            or not all(isinstance(x, str) for x in answer["alternative_causes"])):
        raise ValueError("Expected zero to two text alternative hypotheses")
    if (not isinstance(answer["techniques_considered"], list)
            or not 2 <= len(answer["techniques_considered"]) <= 5
            or not all(isinstance(x, str) for x in answer["techniques_considered"])):
        raise ValueError("Expected two to five text technique names")
    return answer


def render(answer):
    lines = [
        "# VC9 byte-match diagnosis", "",
        "**Observed:** " + answer["observed_difference"], "",
        "**Leading hypothesis (%s):** %s" % (answer["confidence"], answer["most_likely_cause"]), "",
    ]
    if answer["alternative_causes"]:
        lines.extend(["**Alternatives:** " + "; ".join(answer["alternative_causes"]), ""])
    lines.extend(["**One discriminating diagnostic:** " + answer["best_next_diagnostic"], "",
                  "**Techniques:** " + ", ".join(answer["techniques_considered"]), ""])
    return "\n".join(lines)


def new_output_folder(work: Path, model: str) -> Path:
    root = work / "diagnoses"
    root.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", model)
    for number in range(1, 10000):
        folder = root / ("%s_%03d" % (safe, number))
        try:
            folder.mkdir()
            return folder
        except FileExistsError:
            continue
    raise RuntimeError("No free diagnosis folder")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, help="auto_match folder containing search.sqlite3")
    parser.add_argument("--models", type=Path, default=ROOT / "config.model-profiles.json")
    parser.add_argument("--model", default="inkling-mini")
    parser.add_argument("--allow-remote", action="store_true")
    parser.add_argument("--full-catalog", action="store_true", help="Use the full 79-item technique library")
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--dry-run", action="store_true", help="Save request only, no model inference")
    args = parser.parse_args(argv)
    if args.max_tokens < 128:
        parser.error("--max-tokens must be >= 128")
    try:
        work = locate_state(args.work_dir)
        search = ReadOnlyCandidates(work)
        try:
            evidence = assemble_evidence(search, args.full_catalog)
        finally:
            search.db.close()
        messages = [
            {"role": "system", "content": PROMPT.read_text(encoding="utf-8")},
            {"role": "user", "content": json.dumps(evidence, ensure_ascii=False)},
        ]
        output = new_output_folder(work, args.model)
        (output / "request.json").write_text(json.dumps({
            "profile": args.model, "messages": messages,
            "created_utc": datetime.now(timezone.utc).isoformat(),
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        print("Best candidate: " + evidence["best_candidate_path"], flush=True)
        print("Diagnosis request: " + str(output / "request.json"), flush=True)
        if args.dry_run:
            print("Dry-run only: no model contacted; source and DB unchanged", flush=True)
            return 0
        profile = load_profile(args.models, args.model, allow_remote=args.allow_remote)
        answer, metadata = chat_json(profile, messages, max_tokens=args.max_tokens)
        (output / "response.json").write_text(json.dumps({
            "answer": answer, "metadata": metadata,
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        diagnosis = render(validate_answer(answer))
        (output / "diagnosis.md").write_text(diagnosis, encoding="utf-8")
        print(diagnosis, flush=True)
        print("Saved: " + str(output / "diagnosis.md"), flush=True)
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, sqlite3.Error) as exc:
        print("diagnose_match: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
