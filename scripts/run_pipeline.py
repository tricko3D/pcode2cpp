#!/usr/bin/env python3
"""Run Ghidra -> one model reconstruction -> VC9/C2Scope -> optional AI fallback.

No Jupyter, no model tool calls. The mechanical search and proof code remain
in auto_match.py. Currently the verification adapter supports Spore 0x00672cf0.
"""

import argparse
import json
from pathlib import Path
import re
import sys

# Running `python scripts/run_pipeline.py` puts scripts/ on sys.path, not
# necessarily the repository root. Ghidra/context imports need pcode2cpp/.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from . import ai_fallback as AI
    from . import auto_match as A
    from . import build_prompt as BP
    from . import repair_candidate as Repair
    from . import check_candidate as Check
    from .model_client import chat_json, load_profile
    from .probe_body import PREFIX, ROOT
except ImportError:
    import ai_fallback as AI
    import auto_match as A
    import build_prompt as BP
    import repair_candidate as Repair
    import check_candidate as Check
    from model_client import chat_json, load_profile
    from probe_body import PREFIX, ROOT


def initial_messages(context: dict, callees: dict, missing: list) -> list[dict]:
    instruction = (ROOT / 'prompts/reconstruct.txt').read_text(encoding='utf-8')
    if not instruction.strip():
        raise ValueError('Missing reconstruction prompt')
    # This is a separate CLI-only generation contract, not an alteration to
    # the original local one-shot pcode2cpp translator.
    system = (instruction.split('\nOUTPUT\n', 1)[0].strip() + '\n\n'
              'OUTPUT FORMAT OVERRIDE: Return ONLY a JSON object containing a '
              'single string key "body". The value must be C++ statements that '
              'complete the fixed function shown below. No signature, no '
              'outer braces, no explanation, no Markdown, no inline assembly.')
    evidence = BP.render_prompt(context, 'Reconstruct the primary function from the evidence.',
                                callees, missing)
    user = (evidence + '\n\n## Required fixed function prefix\n'
            'The following declarations are provided by the harness. '
            'Only supply the function body; do not modify these declarations.\n\n'
            '```cpp\n' + PREFIX + '    // YOUR BODY HERE\n}\n```\n'
            'Return {"body":"..."} using valid JSON escaping.')
    return [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}]


def write_candidate(path: Path, answer: dict):
    body = answer.get('body')
    if not isinstance(body, str) or not body.strip():
        raise ValueError('Initial model must return nonempty JSON body string')
    if AI.FORBIDDEN.search(body):
        raise ValueError('Initial model returned inline assembly or preprocessor directives')
    path.write_text(PREFIX + body.strip() + '\n}\n', encoding='utf-8')


def reconstruct(args, initial_profile: dict) -> Path:
    """Perform isolated, repeatable initial translation without notebooks."""
    if args.address != 0x00672cf0:
        raise ValueError('This Spore verifier prototype currently supports only 0x00672cf0')
    location = (args.run_dir or ROOT / 'cases/00672cf0/full_pipeline' /
                initial_profile['name']).expanduser().resolve()
    location.mkdir(parents=True, exist_ok=True)
    final = location / 'initial_candidate.cpp'
    if final.is_file():
        print('Reusing initial candidate: ' + str(final), flush=True)
        return final
    context_path = (args.context or location / 'context.json').expanduser().resolve()
    if args.context:
        from pcode2cpp.context import load_context
        context = load_context(context_path)
    elif context_path.is_file():
        from pcode2cpp.context import load_context
        context = load_context(context_path)
    else:
        cfg = json.loads(args.config.expanduser().read_text(encoding='utf-8'))
        from pcode2cpp.ghidra import export_function
        print('Stage: export Ghidra context', flush=True)
        context = export_function(args.address, context_path, cfg['ghidra'])
    if int(context['function']['address'], 16) != args.address:
        raise ValueError('Ghidra context has a different function address')
    callees, missing = BP.read_direct_callees(context, args.callees_dir.expanduser())
    messages = initial_messages(context, callees, missing)
    (location / 'initial_request.json').write_text(json.dumps({
        'profile': initial_profile['name'], 'model': initial_profile['model'],
        'messages': messages,
    }, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f'Stage: initial reconstruction with {initial_profile["name"]}', flush=True)
    response, metadata = chat_json(initial_profile, messages)
    (location / 'initial_response.json').write_text(json.dumps({
        'response': response, 'metadata': metadata,
    }, indent=2, ensure_ascii=False), encoding='utf-8')
    versioned = location / 'initial_v001.cpp'
    write_candidate(versioned, response)
    attempted = versioned
    for attempt in range(args.repairs + 1):
        result = Check.check_candidate(attempted)
        if result.passed:
            final.write_text(attempted.read_text(encoding='utf-8'), encoding='utf-8')
            return final
        if attempt >= args.repairs:
            raise RuntimeError(f'Initial C++ failed Clang after {attempt} repairs: '
                               f'{result.diagnostics_path}')
        errors = Repair.concise_errors(result.diagnostics)
        if not errors:
            raise RuntimeError(f'No actionable compiler diagnostics: {result.diagnostics_path}')
        repair_msgs = Repair.make_messages(Repair.extract_body(attempted.read_text()), errors)
        repair_response, meta = chat_json(initial_profile, repair_msgs)
        nxt = location / f'initial_repair_{attempt+1:03d}.cpp'
        write_candidate(nxt, repair_response)
        (location / f'initial_repair_{attempt+1:03d}.response.json').write_text(json.dumps({
            'response': repair_response, 'metadata': meta,
        }, indent=2), encoding='utf-8')
        attempted = nxt
    raise RuntimeError('Unreachable initial reconstruction state')


def build_engine_args(args, seed: Path):
    switches = ['--seed', str(seed), '--spore-repo', str(args.spore_repo),
                '--c2scope-repo', str(args.c2scope_repo),
                '--max-compiles', str(args.max_compiles),
                '--max-generations', str(args.max_generations),
                '--workers', str(args.workers), '--beam-width', str(args.beam_width)]
    if args.work_dir:
        switches.extend(['--work-dir', str(args.work_dir)])
    return A.build_parser().parse_args(switches)


def build_parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--address', type=lambda x: int(x, 0), default=0x00672cf0)
    p.add_argument('--seed', type=Path, help='Existing candidate to skip Ghidra and initial LLM')
    p.add_argument('--context', type=Path, help='Existing Ghidra JSON to skip export')
    p.add_argument('--config', type=Path, default=ROOT / 'config.json')
    p.add_argument('--callees-dir', type=Path, default=ROOT / 'data/retail-contexts')
    p.add_argument('--models', type=Path, default=ROOT / 'config.model-profiles.json')
    p.add_argument('--initial-model', default='inkling-small')
    p.add_argument('--fallback-model', help='Optional model called after mechanical stagnation')
    p.add_argument('--allow-remote', action='store_true',
                   help='Explicit consent to send prompt/source to a remote HTTPS provider')
    p.add_argument('--run-dir', type=Path, help='Initial reconstruction artifacts')
    p.add_argument('--work-dir', type=Path, help='Separate auto_match SQLite search folder')
    p.add_argument('--spore-repo', type=Path, default=Path.home() / 'spore-decomp')
    p.add_argument('--c2scope-repo', type=Path, default=Path.home() / 'c2scope')
    p.add_argument('--max-compiles', type=int, default=2000)
    p.add_argument('--max-generations', type=int, default=6)
    p.add_argument('--beam-width', type=int, default=16)
    p.add_argument('--workers', type=int, default=16)
    p.add_argument('--repairs', type=int, default=1)
    p.add_argument('--ai-rounds', type=int, default=2)
    p.add_argument('--ai-patches', type=int, default=6)
    p.add_argument('--ai-compiles-per-round', type=int, default=400)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.address != 0x00672cf0:
        parser.error('Only the Spore 0x00672CF0 pilot has a VC9/Unicorn/angr adapter today')
    if min(args.max_compiles, args.max_generations, args.beam_width, args.workers,
           args.ai_rounds, args.ai_patches, args.ai_compiles_per_round) < 1 or args.repairs < 0:
        parser.error('Budgets must be positive and repairs nonnegative')
    try:
        initial = (load_profile(args.models, args.initial_model, allow_remote=args.allow_remote)
                   if args.seed is None else None)
        fallback = (load_profile(args.models, args.fallback_model, allow_remote=args.allow_remote)
                    if args.fallback_model else None)
        seed = args.seed.expanduser().resolve() if args.seed else reconstruct(args, initial)
        engine = A.Engine(build_engine_args(args, seed))
        if fallback is None:
            print('Stage: mechanical-only VC9/C2Scope', flush=True)
            return engine.run()
        return AI.run_with_fallback(engine, fallback,
                                    rounds=args.ai_rounds, patches=args.ai_patches,
                                    compiles_per_round=args.ai_compiles_per_round)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f'run_pipeline: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
