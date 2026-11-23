#!/usr/bin/env python3
"""Opt-in AI source mutations AFTER a VC9/C2Scope mechanical search plateaus.

Uses the existing auto_match SQLite search, fingerprint, Unicorn and angr
backends. It does not grant the model tools or trust model semantic claims.
"""

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import sys

try:
    from . import auto_match as A
    from .model_client import chat_json, load_profile
except ImportError:
    import auto_match as A
    from model_client import chat_json, load_profile


FORBIDDEN = re.compile(r"(?im)\b(?:__asm|_asm|__emit|_emit|asm)\b|__declspec\s*\(\s*naked\s*\)|^\s*#")
FUNCTION = 'InklingCandidate_s00672cf0::FUN_00672cf0'


def apply_edit(source: str, entry: dict) -> str:
    """Apply exactly one source-body edit from the model's JSON response."""
    if not isinstance(entry, dict):
        raise ValueError("Edit must be an object")
    before, after = entry.get("find"), entry.get("replace")
    if not isinstance(before, str) or not before or not isinstance(after, str):
        raise ValueError("Every edit requires nonempty find and string replace")
    if len(before) > 2500 or len(after) > 2500:
        raise ValueError("Edit exceeds 2500-character safety bound")
    start = source.find(FUNCTION)
    if start < 0:
        raise ValueError("Expected the existing VC9 member function")
    body_start = source.find('{', start)
    body_end = source.rfind('}')
    if body_start < 0 or body_end <= body_start:
        raise ValueError("Unable to locate method body")
    body = source[body_start+1:body_end]
    if body.count(before) != 1:
        raise ValueError("Find string must occur exactly once in the function body")
    if FORBIDDEN.search(after) or '#' in after:
        raise ValueError("Inline assembly, compiler directives and naked functions forbidden")
    output = source[:body_start+1] + body.replace(before, after, 1) + source[body_end:]
    if after.count("{") - before.count("{") != after.count("}") - before.count("}"):
        raise ValueError("Edits may not unbalance function braces")
    if output == source or output.count(FUNCTION) != 1:
        raise ValueError("No source change")
    return output


def build_messages(candidate: str, retail: str, compiled: str, score: tuple[int, int],
                   history: list[dict], count: int) -> list[dict]:
    diffs = ''.join(difflib.unified_diff(
        retail.splitlines(keepends=True), compiled.splitlines(keepends=True),
        fromfile='retail', tofile='vc9_candidate'))
    context = {
        'goal': 'VC9/2008 SP1 exact binary match for Spore x86 0x00672cf0',
        'rdiff': score[0], 'bdiff': score[1], 'model_role': 'suggest source experiments only',
        'vc9_flags': '/O2 /MD /Gy /EHsc /TP',
        'current_source': candidate,
        'retail_assembly': retail,
        'compiled_assembly': compiled,
        'assembly_diff': diffs,
        'recent_compiler_experiments': history[-12:],
    }
    system = (
        'You are proposing C++ source mutations for a verified VC9 decompilation. '
        'The C++ must be compiled with the historical Microsoft VC9 optimizer; '
        'do not attempt to manually write assembly or claim equivalence. '
        'C2Scope and VC9 have already performed extensive mechanical rewrites and stalled. '
        'Find new, non-obvious source structures that may change the exact instruction ordering. '
        'Preserve the ABI, calls, observable memory behavior and function signature. '
        'Prioritize source-level register lifetimes, alias declarations, field access '
        'dependencies, expressions, and statement structure. '
        'Every proposal MUST be an independent, minimal textual substitution in the '
        'existing function body. It is a hypothesis and will be compiled and formally checked. '
        'Never return #directives, inline assembly, naked functions or a complete new function. '
        f'Return ONLY a JSON object {{"edits":[{{"find":"exact original substring",'
        f'"replace":"replacement substring","hypothesis":"short explanation"}}]}} '
        f'with at most {count} independent edits. Do not provide reasoning outside the JSON.'
    )
    return [{'role': 'system', 'content': system},
            {'role': 'user', 'content': json.dumps(context, ensure_ascii=False)}]


def best_candidate(store):
    proven = store.best_proven()
    if proven is not None:
        return proven
    candidates = [r for r in store.all() if r['snapshot'] is not None
                  and r['status'] not in ('VC9_FAILED', 'UNSAFE', 'ERROR')]
    if not candidates:
        raise RuntimeError('No compiled candidate to refine')
    return min(candidates, key=lambda r: (r['rdiff'] if r['rdiff'] is not None else 9999,
                                          r['bdiff'] if r['bdiff'] is not None else 9999))


def is_match(store) -> bool:
    return any(r['status'] == 'MATCH' for r in store.all())


def produce_round(engine, profile: dict, round_no: int, patches: int) -> list[str]:
    """Make one model request and persist the exact response before evaluation."""
    store = engine.store
    identity = hashlib.sha256((profile['name'] + profile['model'] + profile['url']).encode()).hexdigest()[:12]
    tag = f'ai_{profile["name"]}_{identity}_round{round_no:02d}'
    key = f'ai_fallback_v1:{tag}'
    cached = store.getmeta(key)
    if cached is not None:
        print(f'AI round {round_no}: resuming {len(cached["ids"])} saved variants', flush=True)
        return cached['ids']
    parent = best_candidate(store)
    snap = json.loads(parent['snapshot'])
    candidate = Path(parent['path']).read_text(encoding='utf-8')
    retail = Path(snap['original_asm']).read_text(encoding='utf-8')
    ours = Path(snap['candidate_asm']).read_text(encoding='utf-8')
    history = [dict(origin=r['origin'], rdiff=r['rdiff'], bdiff=r['bdiff'],
                    status=r['status']) for r in store.all()
               if r['snapshot'] and r['id'] != parent['id']]
    messages = build_messages(candidate, retail, ours,
                              (parent['rdiff'] or 0, parent['bdiff'] or 0), history, patches)
    logs = store.log_dir
    (logs / f'{tag}.request.json').write_text(json.dumps({
        'model': profile['model'], 'profile': profile['name'],
        'parent': parent['id'], 'messages': messages,
    }, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f'AI round {round_no}: {profile["name"]} on rdiff={parent["rdiff"]}, '
          f'bdiff={parent["bdiff"]}; requesting up to {patches} edits', flush=True)
    answer, usage = chat_json(profile, messages)
    (logs / f'{tag}.response.json').write_text(json.dumps({
        'answer': answer, 'metadata': usage,
    }, indent=2, ensure_ascii=False), encoding='utf-8')
    edits = answer.get('edits')
    if not isinstance(edits, list):
        raise RuntimeError('Model must return a JSON object containing an edits array')
    ids, rejected = [], []
    for i, proposal in enumerate(edits[:patches]):
        try:
            variant = apply_edit(candidate, proposal)
            ident = store.add(variant, parent['id'], f'ai:{profile["name"]}:{round_no}:{i}',
                              parent['generation'] + 1, parent['rdiff'], parent['bdiff'])
            if ident != parent['id'] and ident not in ids:
                ids.append(ident)
        except (ValueError, TypeError) as exc:
            rejected.append({'index': i, 'reason': str(exc)})
    store.meta(key, {'ids': ids, 'parent': parent['id'], 'rejected': rejected,
                     'profile': profile['name']})
    print(f'  Accepted {len(ids)} novel source proposals, rejected {len(rejected)}', flush=True)
    return ids


def run_with_fallback(engine: A.Engine, profile: dict, *, rounds: int,
                      patches: int, compiles_per_round: int, mechanical_first=True,
                      sweeps_per_round=2) -> int:
    """Mechanics first, AI after plateau, then mechanics again for each round."""
    if mechanical_first:
        print('Stage: mechanical VC9/C2Scope search first', flush=True)
        engine.run()
    if is_match(engine.store):
        print('Already an exact fingerprint MATCH; no AI fallback required', flush=True)
        return 0
    for n in range(1, rounds + 1):
        if is_match(engine.store):
            return 0
        ids = produce_round(engine, profile, n, patches)
        if not ids:
            print("No distinct AI source proposals; skipping this round's compiler budget", flush=True)
            continue
        identity = hashlib.sha256((profile['name']+profile['model']+profile['url']).encode()).hexdigest()[:12]
        budget_key = f'ai_fallback_budget_v1:{profile["name"]}:{identity}:{n}'
        ceiling = engine.store.getmeta(budget_key)
        if ceiling is None:
            ceiling = max(engine.store.count(), engine.a.max_compiles) + compiles_per_round
            engine.store.meta(budget_key, ceiling)
        engine.a.max_compiles = ceiling
        ranked = []
        for ident in ids:
            row = engine.store.row(ident)
            if row['snapshot'] is None:
                if engine.remaining() < 1:
                    break
                engine.evaluate(ident, do_unicorn=True, do_proof=True)
            row = engine.store.row(ident)
            if row['snapshot'] is not None and row['status'] not in ('VC9_FAILED', 'UNSAFE', 'ERROR'):
                ranked.append(row)
            if is_match(engine.store):
                engine.summary()
                return 0
        ranked.sort(key=lambda r: (r['rdiff'] if r['rdiff'] is not None else 9999,
                                   r['bdiff'] if r['bdiff'] is not None else 9999))
        for row in ranked[:sweeps_per_round]:
            if engine.remaining() < engine.a.min_sweep_budget:
                break
            if not row['expanded']:
                engine.enqueue_field_mutations(row)
                engine.enqueue_schedule_mutations(row)
                engine.sweep(row)
        print(f'Stage: mechanical refinement of AI round {n} '
              f'({engine.store.count()} / {engine.a.max_compiles} estimated compiles)', flush=True)
        engine.run()
        if is_match(engine.store):
            return 0
    engine.summary()
    return 0 if engine.store.best_proven() else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--models', type=Path, default=Path('config.model-profiles.json'))
    parser.add_argument('--model', required=True, help='Named model profile, e.g. inkling-small or deepseek')
    parser.add_argument('--allow-remote', action='store_true')
    parser.add_argument('--ai-rounds', type=int, default=2)
    parser.add_argument('--ai-patches', type=int, default=6)
    parser.add_argument('--ai-compiles-per-round', type=int, default=400)
    parser.add_argument('--ai-sweeps-per-round', type=int, default=2)
    parser.add_argument('--skip-mechanical', action='store_true',
                        help='Only for resuming an already completed mechanical search')
    args, remaining = parser.parse_known_args(argv)
    engine_args = A.build_parser().parse_args(remaining)
    if min(args.ai_rounds, args.ai_patches, args.ai_compiles_per_round) < 1 or args.ai_sweeps_per_round < 0:
        parser.error('AI round and budget counts must be positive')
    try:
        profile = load_profile(args.models, args.model, allow_remote=args.allow_remote)
        engine = A.Engine(engine_args)
        return run_with_fallback(engine, profile, rounds=args.ai_rounds,
                                 patches=args.ai_patches,
                                 compiles_per_round=args.ai_compiles_per_round,
                                 sweeps_per_round=args.ai_sweeps_per_round,
                                 mechanical_first=not args.skip_mechanical)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f'ai_fallback: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
