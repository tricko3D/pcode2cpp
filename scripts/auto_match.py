#!/usr/bin/env python3
"""Resumable, compiler-guided search for the Spore 0x00672cf0 VC9 function.

The search operates on isolated, VC9-ready translation units. It delegates
rewrite enumeration and assembly scoring to C2Scope, and correctness checking
to Spore's own fingerprint, Unicorn differential test, and angr proof. No
tracked Spore source/manifest is edited, and no model is needed after the seed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import time

try:
    from . import c2scope_feedback as C
    from .probe_body import PREFIX, ROOT
    from .prove_spore_candidate import prepare_source
except ImportError:
    import c2scope_feedback as C
    from probe_body import PREFIX, ROOT
    from prove_spore_candidate import prepare_source

DEFAULT_FAMILIES = "wrap,alias,swap,split,touch,paren,subst,reread,const,unalias"
# This is an intentionally Spore-specific VC9 prototype. A generic frontend can
# supply another snapshot/verification backend without changing the search.
FUNC = C.FUNC
FLAGS = C.FLAGS
BASELINE_RE = re.compile(r"baseline:\s*\d+ instructions,\s*rdiff\s+(\d+),\s*bdiff\s+(\d+)")
ROW_RE = re.compile(r"^\s+(v\d{4})\s+\w+\s+\d+\s+\d+\s+(\d+)\*?\s+(\d+)\s+\d+\s+", re.M)
COMBO_RE = re.compile(r"^\s+(v\d{4}(?:\+v\d{4})+)\s+shape\s+\d+\s+regs\s+\d+\s+rdiff\s+(\d+)\s+bdiff\s+(\d+)", re.M)
OUT_RE = re.compile(r"^variants:\s*(.+)/v<id>/v<id>\.cpp\s*$", re.M)
COUNT_RE = re.compile(r"\b(\d+) variables,\s*\d+ statements,\s*(\d+) variants")
MEASURED_RE = re.compile(r"\b(\d+) measured,\s*\d+ failed")
NUM = r"(?:0[xX][0-9a-fA-F]+|\d+)"
STORE_RE = re.compile(
    rf"(?P<lhs>(?:hs_bind\(\s*)?(?P<ptr>param_1)(?:\s*\))?)"
    rf"\s*\[\s*(?P<slot>{NUM})\s*\]\s*=\s*"
    rf"\(\s*int\s*\)\s*\(\s*(?P=ptr)\s*\+\s*(?P<offset>{NUM})\s*\)\s*;"
)


def digest(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def field_dependency_mutations(source: str):
    """Re-express a pointer offset via an earlier stored pointer-valued field.

    C2Scope's current generic rewrite families don't propose this. This is a
    candidate generator, NOT a claim of alias-safe semantic equivalence.
    Only the independent verifier can promote the resulting source.
    """
    stores = list(STORE_RE.finditer(source))
    for dest in stores:
        for prior in stores:
            if prior.start() >= dest.start():
                break
            if prior.group("ptr") != dest.group("ptr"):
                continue
            if prior.group("slot") == dest.group("slot"):
                continue
            offset = (int(dest.group("offset"), 0) - int(prior.group("offset"), 0)) * 4
            if not 0 <= offset <= 4096:
                continue
            # A write through another lvalue or a call in between may alias
            # prior's field. Such candidates are still useful for *search*,
            # but must never be silently treated as equivalent.
            span = dest.span()
            changed = (dest.group(0)[:dest.group(0).find("=") + 1]
                       + f" (int)((unsigned int){dest.group('ptr')}[{prior.group('slot')}] + 0x{offset:x}u);")
            output = source[:span[0]] + changed + source[span[1]:]
            if output != source:
                yield f"field:{dest.group('ptr')}[{dest.group('slot')}]<-{prior.group('slot')}", output


def parse_sweep(log: str) -> tuple[tuple[int, int] | None, list[tuple[str, int, int, Path]], int]:
    """Parse *measured* C2Scope candidates and their paths, never invent scores."""
    base = BASELINE_RE.search(log)
    root = OUT_RE.search(log)
    measured = MEASURED_RE.search(log)
    score = (int(base[1]), int(base[2])) if base else None
    if not root:
        return score, [], int(measured[1]) if measured else 0
    directory = Path(root[1].strip())
    found = []
    for match in ROW_RE.finditer(log):
        name, rd, bd = match.groups()
        found.append((name, int(rd), int(bd), directory / name / (name + ".cpp")))
    for match in COMBO_RE.finditer(log):
        name, rd, bd = match.groups()
        ident = "c_" + "_".join(p[1:] for p in name.split("+"))
        found.append((name, int(rd), int(bd), directory / ident / (ident + ".cpp")))
    found.sort(key=lambda x: (x[1], x[2], x[0]))
    return score, found, int(measured[1]) if measured else 0


def copy_prepared(repo: Path, source: Path, name: str) -> Path:
    """The Spore proof worker only accepts files under ignored work/."""
    root = repo / "work" / "pcode2cpp_checks"
    root.mkdir(parents=True, exist_ok=True)
    out = root / ("auto_match_" + name + ".cpp")
    data = source.read_bytes()
    if out.exists():
        if out.read_bytes() != data:
            raise ValueError(f"Prepared file collision: {out}")
    else:
        out.write_bytes(data)
    return out


def normalize_seed(repo: Path, source: Path) -> str:
    src = source.read_text(encoding="utf-8")
    if src.startswith(PREFIX):
        return prepare_source(repo, source).read_text(encoding="utf-8")
    if "InklingCandidate_s00672cf0::FUN_00672cf0" not in src:
        raise ValueError("Seed must be an original Inkling probe or a prepared VC9 candidate")
    return src


def proof_worker(repo: Path, prepared: Path, directory: Path, label: str, timeout: int) -> str:
    cmd = [str(repo / ".venv/bin/python"), str((ROOT / "scripts/prove_spore_candidate.py").resolve()),
           "--worker", "--spore-repo", str(repo), "--prepared-source", str(prepared),
           "--timeout", str(timeout)]
    try:
        completed = subprocess.run(cmd, cwd=repo, capture_output=True, text=True,
                                   timeout=timeout * 8 + 90, check=False)
        output = completed.stdout + completed.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        output = f"ERROR: {exc}\n"
    (directory / f"{label}.formal.log").write_text(output, encoding="utf-8")
    match = re.search(r"(?m)^(MATCH|EQUIVALENT|REFUTED|UNKNOWN) 0x00672cf0\b", output)
    return match[1] if match else "ERROR"


class Store:
    def __init__(self, root: Path):
        self.root = root
        self.source_dir = root / "sources"
        self.log_dir = root / "logs"
        self.source_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(root / "search.sqlite3")
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS candidates (
                id TEXT PRIMARY KEY, path TEXT NOT NULL, parent TEXT, origin TEXT NOT NULL,
                generation INTEGER NOT NULL, rdiff INTEGER, bdiff INTEGER,
                machine TEXT, fingerprint TEXT, empirical TEXT, proof TEXT,
                status TEXT NOT NULL DEFAULT 'NEW', expanded INTEGER NOT NULL DEFAULT 0,
                snapshot TEXT, note TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_candidates_machine ON candidates(machine);
            CREATE TABLE IF NOT EXISTS sweeps (
                parent TEXT PRIMARY KEY, status TEXT NOT NULL, output TEXT,
                measured INTEGER NOT NULL DEFAULT 0, estimated_compiles INTEGER NOT NULL DEFAULT 0
            );
        """)
        self.db.commit()

    def getmeta(self, key, fallback=None):
        x = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(x[0]) if x else fallback

    def meta(self, key, val):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, json.dumps(val)))
        self.db.commit()

    def count(self) -> int:
        return self.getmeta("estimated_compiles", 0)

    def debit(self, n: int):
        self.meta("estimated_compiles", self.count() + n)

    def add(self, src: str, parent: str | None, origin: str, generation: int,
            rdiff: int | None, bdiff: int | None):
        ident = digest(src)
        path = self.source_dir / f"{ident[:20]}.cpp"
        if path.exists():
            if path.read_text(encoding="utf-8") != src:
                raise ValueError("Source hash prefix collision")
        else:
            path.write_text(src, encoding="utf-8")
        self.db.execute("""
            INSERT OR IGNORE INTO candidates
                (id,path,parent,origin,generation,rdiff,bdiff) VALUES (?,?,?,?,?,?,?)
        """, (ident, str(path), parent, origin, generation, rdiff, bdiff))
        self.db.commit()
        prior = self.row(ident)
        if (prior["rdiff"] is None or rdiff is not None and
                (rdiff, bdiff if bdiff is not None else 10000) <
                (prior["rdiff"], prior["bdiff"] if prior["bdiff"] is not None else 10000)):
            self.update(ident, rdiff=rdiff, bdiff=bdiff)
        return ident

    def row(self, ident):
        return self.db.execute("SELECT * FROM candidates WHERE id=?", (ident,)).fetchone()

    def update(self, ident, **fields):
        if not fields:
            return
        if not set(fields) <= {"rdiff", "bdiff", "machine", "fingerprint", "empirical",
                              "proof", "status", "expanded", "snapshot", "note"}:
            raise ValueError("Unexpected database update field")
        self.db.execute("UPDATE candidates SET " + ",".join(k + "=?" for k in fields) + " WHERE id=?",
                        (*fields.values(), ident))
        self.db.commit()

    def all(self):
        return self.db.execute("SELECT * FROM candidates").fetchall()

    def eligible(self, beam_width: int, max_per_machine: int) -> list:
        """Best-scored frontier, with reserved space for dataflow exploration."""
        rows = [r for r in self.all() if not r["expanded"] and r["status"] not in
                ("VC9_FAILED", "UNSAFE", "ERROR")]
        rows.sort(key=lambda r: (r["rdiff"] if r["rdiff"] is not None else 10000,
                                 r["bdiff"] if r["bdiff"] is not None else 10000,
                                 r["generation"], r["id"]))
        selected, counts = [], {}
        def include(r):
            key = r["machine"] or r["id"]
            if counts.get(key, 0) >= max_per_machine:
                return False
            selected.append(r)
            counts[key] = counts.get(key, 0) + 1
            return True
        # Dataflow mutations don't initially have C2Scope scores. Reserve a
        # lane so they aren't permanently starved by scored rwsweep variants.
        specials = [r for r in rows if r["origin"].startswith("field:")]
        for r in specials[:min(2, beam_width)]:
            include(r)
        for r in rows:
            if len(selected) >= beam_width:
                break
            if r not in selected:
                include(r)
        return selected

    def best_proven(self):
        rows = [r for r in self.all() if r["proof"] in ("MATCH", "EQUIVALENT")]
        return min(rows, key=lambda r: (r["rdiff"] if r["rdiff"] is not None else 10000,
                                        r["bdiff"] if r["bdiff"] is not None else 10000)) if rows else None


def snapshot_prepared(repo: Path, candidate: Path, case: Path, tag: str):
    """Use the existing C2Scope-feedback VC9 worker, without probe rewrapping."""
    prepared = copy_prepared(repo, candidate, tag)
    original_asm = case / "original.s"
    mine = case / f"{tag}.s"
    report = case / f"{tag}.snapshot.json"
    cmd = [str(repo / ".venv/bin/python"), str((ROOT / "scripts/c2scope_feedback.py").resolve()),
           "--worker-snapshot", "--spore-repo", str(repo), "--prepared", str(prepared),
           "--original-asm", str(original_asm), "--candidate-asm", str(mine), "--report", str(report)]
    proc = subprocess.run(cmd, cwd=repo, capture_output=True, text=True, timeout=180, check=False)
    (case / f"{tag}.vc9.log").write_text(proc.stdout + proc.stderr, encoding="utf-8")
    if proc.returncode or not report.is_file():
        raise RuntimeError(f"VC9 snapshot failed: {(proc.stdout + proc.stderr)[-800:]}")
    state = json.loads(report.read_text(encoding="utf-8"))
    if state.get("status") != "COMPILED":
        raise RuntimeError(f"VC9 status {state.get('status')}: {state.get('fingerprint')}")
    state["prepared"] = str(prepared)
    return state


class Engine:
    def __init__(self, args):
        self.a = args
        self.seed = args.seed.expanduser().resolve()
        self.repo = args.spore_repo.expanduser().resolve()
        self.c2root = args.c2scope_repo.expanduser().resolve()
        if not self.seed.is_file():
            raise ValueError(f"Seed not found: {self.seed}")
        if not (self.repo / "tools/difftest/equiv.py").is_file():
            raise ValueError(f"Spore checkout unavailable: {self.repo}")
        if not (self.c2root / "tools/rwsweep.py").is_file():
            raise ValueError(f"C2Scope checkout unavailable: {self.c2root}")
        if not (self.repo / ".venv/bin/python").is_file():
            raise ValueError("Spore virtual environment unavailable")
        initial = normalize_seed(self.repo, self.seed)
        stem = digest(initial)[:12]
        work = (args.work_dir or ROOT / "cases/00672cf0/auto_match" / stem).expanduser().resolve()
        self.store = Store(work)
        settings = {"seed": digest(initial), "repo": str(self.repo), "c2root": str(self.c2root),
                    "families": args.families, "func": FUNC, "flags": list(FLAGS)}
        previous = self.store.getmeta("settings")
        if previous is not None and previous != settings:
            raise ValueError("Existing work-dir has different seed/toolchain/families; use another --work-dir")
        self.store.meta("settings", settings)
        self.seed_id = self.store.add(initial, None, "seed", 0, None, None)
        print(f"Search: {work}\nSeed: {self.seed}\nEstimated compiles used: {self.store.count()}", flush=True)

    def remaining(self):
        return max(0, self.a.max_compiles - self.store.count())

    def evaluate(self, ident, do_unicorn=False, do_proof=False):
        row = self.store.row(ident)
        if row["snapshot"] is None:
            if self.remaining() < 1:
                return False
            tag = ident[:16]
            print(f"VC9 {tag} {row['origin']}", flush=True)
            try:
                state = snapshot_prepared(self.repo, Path(row["path"]), self.store.log_dir, tag)
            except Exception as exc:
                self.store.update(ident, status="VC9_FAILED", note=str(exc))
                self.store.debit(1)
                return False
            self.store.debit(1)
            if not state.get("callee_symbol_valid"):
                self.store.update(ident, status="UNSAFE", fingerprint=state["fingerprint"],
                                  snapshot=json.dumps(state),
                                  note="Unexpected external callee symbol; cannot validate linkage")
                print("  Rejected: external callee symbol not validated", flush=True)
                return False
            machine = state["machine_sha256"]
            prior = next((r for r in self.store.all() if r["id"] != ident and
                          r["machine"] == machine and r["snapshot"]), None)
            vals = {"machine": machine, "fingerprint": state["fingerprint"],
                    "snapshot": json.dumps(state), "status": "DUPLICATE_MACHINE" if prior else "COMPILED"}
            if prior:
                vals["empirical"] = prior["empirical"]
                vals["proof"] = prior["proof"]
            self.store.update(ident, **vals)
            row = self.store.row(ident)
            print(f"  {state['candidate_bytes']} bytes, {state['fingerprint']}"
                  + (" [duplicate machine code]" if prior else ""), flush=True)
        else:
            state = json.loads(row["snapshot"])
        if state["fingerprint"] == "PASS" and state.get("callee_symbol_valid"):
            self.store.update(ident, status="MATCH", proof="MATCH")
            return True
        if row["status"] == "DUPLICATE_MACHINE":
            return False
        prepared = Path(state["prepared"])
        tag = ident[:16]
        if (do_unicorn or do_proof) and row["empirical"] is None:
            try:
                result = C.differential_test(self.repo, str(prepared), self.store.log_dir,
                                             tag, self.a.inputs)
                empirical = result["verdict"]
            except Exception as exc:
                empirical = "ERROR"
                result = {"detail": str(exc)}
            (self.store.log_dir / f"{tag}.unicorn.summary.json").write_text(
                json.dumps(result, indent=2), encoding="utf-8")
            self.store.update(ident, empirical=empirical)
            row = self.store.row(ident)
            print(f"  Unicorn: {empirical}", flush=True)
        if do_proof and row["empirical"] == "PASS" and row["proof"] is None:
            proof = proof_worker(self.repo, prepared, self.store.log_dir, tag,
                                 self.a.proof_timeout)
            self.store.update(ident, proof=proof, status=proof)
            print(f"  Formal: {proof}", flush=True)
        return False

    def sweep(self, row) -> list[str]:
        """Run measured rwsweep, preserve improving variants before next sweep."""
        ident = row["id"]
        old = self.store.db.execute("SELECT * FROM sweeps WHERE parent=?", (ident,)).fetchone()
        if old and old["status"] == "DONE":
            self.store.update(ident, expanded=1)
            return []
        # Each C2Scope invocation compiles the baseline, up to --limit
        # singles and --verify combos. Reserve headroom for snapshots.
        budget = self.remaining()
        if budget < 3:
            return []
        limit = min(self.a.per_parent_limit, max(1, budget - 2 - self.a.verify_combos))
        verify = min(self.a.verify_combos, max(0, budget - 1 - limit))
        source = Path(row["path"])
        cmd = ["uv", "run", "tools/rwsweep.py", str(source),
               "--func", FUNC, "--asm-vs", str(self.store.log_dir / "original.s"),
               "--families", self.a.families, "--jobs", str(self.a.workers),
               "--limit", str(limit), "--max-combo", "2", "--verify", str(verify),
               "--c2", "15.00", "--", *FLAGS]
        env = dict(os.environ, C2TRACE_REMOTE="0")
        env.pop("VIRTUAL_ENV", None)
        log = self.store.log_dir / f"{ident[:16]}.rwsweep.log"
        print(f"Sweep {ident[:12]}: up to {limit} variants; {self.remaining()} compilation budget", flush=True)
        started = time.monotonic()
        try:
            p = subprocess.run(cmd, cwd=self.c2root, env=env, text=True,
                               capture_output=True, timeout=self.a.sweep_timeout, check=False)
            output = p.stdout + p.stderr
            log.write_text(output, encoding="utf-8")
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.store.db.execute("INSERT OR REPLACE INTO sweeps (parent,status,output) VALUES (?,?,?)",
                                  (ident, "ERROR", str(exc)))
            self.store.db.commit()
            self.store.update(ident, expanded=1, note=str(exc))
            print(f"  Sweep failed: {exc}", flush=True)
            return []
        baseline, ranked, measured = parse_sweep(output)
        # A failed/partial sweep must not be treated as exhausted.
        if p.returncode or baseline is None:
            self.store.db.execute("INSERT OR REPLACE INTO sweeps (parent,status,output) VALUES (?,?,?)",
                                  (ident, "ERROR", str(log)))
            self.store.db.commit()
            self.store.update(ident, expanded=1, note=f"sweep exit {p.returncode}: {output[-400:]}")
            print(f"  Sweep exited {p.returncode}; see {log}", flush=True)
            return []
        self.store.update(ident, rdiff=baseline[0], bdiff=baseline[1])
        combos = sum(1 for name, *_ in ranked if "+" in name)
        count = measured + combos + 1
        self.store.debit(count)
        # Stage a diversity-aware selection: multiple rewrites with the same
        # scores can still produce different compiler IR and future mutations.
        outputs, score_seen = [], {}
        for name, rd, bd, path in ranked:
            if not path.is_file():
                continue
            key = (rd, bd)
            if score_seen.get(key, 0) >= self.a.per_score:
                continue
            score_seen[key] = score_seen.get(key, 0) + 1
            src = path.read_text(encoding="utf-8")
            child = self.store.add(src, ident, f"rwsweep:{name}", row["generation"] + 1, rd, bd)
            if child != ident:
                outputs.append(child)
            if len(outputs) >= self.a.collect_top:
                break
        self.store.db.execute("INSERT OR REPLACE INTO sweeps VALUES (?,?,?,?,?)",
                              (ident, "DONE", str(log), measured, count))
        self.store.db.commit()
        self.store.update(ident, expanded=1)
        print(f"  baseline rdiff={baseline[0]} bdiff={baseline[1]}; measured={measured}; "
              f"improving proposals kept={len(outputs)}; {time.monotonic()-started:.1f}s", flush=True)
        return outputs

    def run(self) -> int:
        if self.remaining() and self.store.row(self.seed_id)["snapshot"] is None:
            if self.evaluate(self.seed_id, do_unicorn=True, do_proof=True):
                self.summary()
                return 0
        for iteration in range(self.a.max_generations):
            if self.remaining() < 2:
                break
            frontier = self.store.eligible(self.a.beam_width, self.a.machine_alternatives)
            if not frontier:
                break
            print(f"\n=== Generation {iteration+1}: {len(frontier)} parents ===", flush=True)
            created = []
            for row in frontier:
                if self.remaining() < 2:
                    break
                # New family: derivation from an earlier, stored pointer value.
                for label, src in field_dependency_mutations(Path(row["path"]).read_text(encoding="utf-8")):
                    child = self.store.add(src, row["id"], label, row["generation"]+1,
                                           row["rdiff"], row["bdiff"])
                    created.append(child)
                created.extend(self.sweep(row))
            # Snapshot the most promising discovered sources, reserving slots
            # for the dataflow family that has only inherited ranking so far.
            fresh = [self.store.row(i) for i in dict.fromkeys(created)
                     if self.store.row(i)["snapshot"] is None and
                     self.store.row(i)["status"] == "NEW"]
            fresh.sort(key=lambda r: (r["rdiff"] if r["rdiff"] is not None else 10000,
                                      r["bdiff"] if r["bdiff"] is not None else 10000))
            special = [r for r in fresh if r["origin"].startswith("field:")]
            ordered = list(dict.fromkeys([r["id"] for r in special[:2]] +
                                         [r["id"] for r in fresh]))
            unicorn_used = proof_used = 0
            for ident in ordered[:self.a.evaluate_top]:
                if self.remaining() < 1:
                    break
                before = self.store.row(ident)
                matched = self.evaluate(ident,
                                        do_unicorn=(unicorn_used < self.a.unicorn_top),
                                        do_proof=(proof_used < self.a.formal_top))
                after = self.store.row(ident)
                if after["status"] != "DUPLICATE_MACHINE":
                    if before["empirical"] is None and after["empirical"] is not None:
                        unicorn_used += 1
                    if before["proof"] is None and after["proof"] is not None:
                        proof_used += 1
                if matched:
                    print(f"MATCH: {self.store.row(ident)['path']}", flush=True)
                    self.summary()
                    return 0
            self.summary()
        best = self.store.best_proven()
        if best:
            print(f"Best proven: {best['path']} ({best['proof']}, rdiff={best['rdiff']}, bdiff={best['bdiff']})",
                  flush=True)
        print(f"Search stopped: estimated {self.store.count()} / {self.a.max_compiles} compiles", flush=True)
        return 0 if best else 1

    def summary(self):
        rows = self.store.all()
        best = self.store.best_proven()
        out = {"seed": str(self.seed), "work_dir": str(self.store.root),
               "estimated_compiles": self.store.count(), "candidates": len(rows),
               "byte_matches": [r["path"] for r in rows if r["status"] == "MATCH"],
               "best_proven": ({"path": best["path"], "proof": best["proof"],
                                "rdiff": best["rdiff"], "bdiff": best["bdiff"]} if best else None),
               "status_counts": {s: sum(1 for r in rows if r["status"] == s)
                                 for s in sorted({r["status"] for r in rows})}}
        (self.store.root / "summary.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
        print("Summary: " + str(self.store.root / "summary.json"), flush=True)


def build_parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--seed", type=Path, default=C.DEFAULT_CANDIDATE)
    p.add_argument("--spore-repo", type=Path, default=Path.home() / "spore-decomp")
    p.add_argument("--c2scope-repo", type=Path, default=Path.home() / "c2scope")
    p.add_argument("--work-dir", type=Path)
    p.add_argument("--beam-width", type=int, default=16)
    p.add_argument("--workers", type=int, default=os.cpu_count() or 16)
    p.add_argument("--max-compiles", type=int, default=2000)
    p.add_argument("--max-generations", type=int, default=6)
    p.add_argument("--per-parent-limit", type=int, default=500)
    p.add_argument("--verify-combos", type=int, default=16)
    p.add_argument("--collect-top", type=int, default=24)
    p.add_argument("--per-score", type=int, default=2)
    p.add_argument("--machine-alternatives", type=int, default=2)
    p.add_argument("--evaluate-top", type=int, default=24)
    p.add_argument("--unicorn-top", type=int, default=8)
    p.add_argument("--formal-top", type=int, default=4)
    p.add_argument("--inputs", type=int, default=700)
    p.add_argument("--proof-timeout", type=int, default=90)
    p.add_argument("--sweep-timeout", type=int, default=1800)
    p.add_argument("--families", default=DEFAULT_FAMILIES)
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    for field in ("beam_width", "workers", "max_compiles", "max_generations",
                  "per_parent_limit", "collect_top", "per_score", "machine_alternatives",
                  "evaluate_top", "inputs", "proof_timeout", "sweep_timeout"):
        if getattr(args, field) <= 0:
            parser.error(f"--{field.replace('_', '-')} must be positive")
    if min(args.formal_top, args.unicorn_top, args.verify_combos) < 0:
        parser.error("verification and combination limits cannot be negative")
    if args.formal_top > args.unicorn_top or args.unicorn_top > args.evaluate_top:
        parser.error("require formal-top <= unicorn-top <= evaluate-top")
    try:
        return Engine(args).run()
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"auto_match: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
