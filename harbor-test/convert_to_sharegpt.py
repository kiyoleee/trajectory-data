# -*- coding: utf-8 -*-
"""
Convert ATIF-v1.7 trajectories under `first-round/` to LLaMA-Factory ShareGPT format.

Filters: keep only trajectories whose verifier/reward.txt parses to a number >= 1.
Output: one .jsonl per (model-family, harness) directory + a merged all.jsonl.
"""
import json
import os
import re
import sys
import io
import argparse
from pathlib import Path

# Force UTF-8 stdio on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

OBS_TRUNC = 6000          # max chars kept per tool observation
MSG_TRUNC = 40000         # max chars kept for any single message


def clean_observation(content: str) -> str:
    """Strip claude-code's '[stdout] ... [metadata] {...}' wrapper; keep the real payload."""
    if not isinstance(content, str):
        content = json.dumps(content, ensure_ascii=False)
    # Cut at the first "\n[stdout]\n" marker if it exists
    idx = content.find('\n[stdout]\n')
    if idx != -1:
        content = content[:idx]
    # Remove trailing "[metadata] {...}" if present
    content = re.sub(r'\n?\[metadata\]\s*\{.*?\}\s*$', '', content, flags=re.DOTALL)
    content = content.strip()
    if len(content) > OBS_TRUNC:
        half = OBS_TRUNC // 2
        content = content[:half] + f'\n\n... [truncated {len(content) - OBS_TRUNC} chars] ...\n\n' + content[-half:]
    return content


def truncate(text: str, limit: int = MSG_TRUNC) -> str:
    if text is None:
        return ''
    if not isinstance(text, str):
        text = json.dumps(text, ensure_ascii=False)
    if len(text) > limit:
        return text[:limit] + f'\n... [truncated {len(text) - limit} chars]'
    return text


def fmt_tool_call(tc: dict) -> str:
    """Render one tool call as a JSON block that the model would emit."""
    fn = tc.get('function_name') or tc.get('extra', {}).get('tool_use_name') or 'unknown'
    args = tc.get('arguments') or tc.get('extra', {}).get('raw_arguments') or {}
    return json.dumps({'name': fn, 'arguments': args}, ensure_ascii=False, indent=2)


def trajectory_to_sharegpt(traj: dict, task_id: str, model: str, harness: str, run_dir: str):
    steps = traj.get('steps', [])
    if not steps:
        return None

    system_parts = []
    conversations = []
    call_names = {}
    seen_task_prompt = False   # the long markdown task description we want as system

    def is_task_prompt(text: str) -> bool:
        t = text.lstrip()
        # task prompts are long markdown task descriptions
        return t.startswith('# ') and ('## Objective' in t or '## Delivery' in t) and len(t) > 2000

    for step in steps:
        src = step.get('source')
        msg = step.get('message') or ''

        if src == 'system':
            system_parts.append(truncate(msg))
            continue

        if src == 'user':
            if not seen_task_prompt and is_task_prompt(msg):
                system_parts.append(truncate(msg))
                seen_task_prompt = True
            else:
                # environment_context and other harness-injected user turns:
                # fold into system if no assistant turn yet, else skip (noise)
                if not any(c['from'] == 'gpt' for c in conversations):
                    if msg.strip() and len(msg) < 5000:
                        system_parts.append(truncate(msg))
                # else: drop (rare mid-conversation user interruptions)
            continue

        if src != 'agent':
            continue

        # assistant turn
        tcs = step.get('tool_calls') or []
        pieces = []
        if msg.strip():
            pieces.append(msg.strip())
        for tc in tcs:
            call_names[tc.get('tool_call_id')] = tc.get('function_name')
            pieces.append('<tool_call>\n' + fmt_tool_call(tc) + '\n</tool_call>')
        assistant_value = '\n\n'.join(pieces)
        if assistant_value:
            conversations.append({'from': 'gpt', 'value': truncate(assistant_value)})

        obs = step.get('observation') or {}
        for r in obs.get('results') or []:
            tool_name = call_names.get(r.get('source_call_id'), 'tool')
            content = clean_observation(r.get('content', ''))
            is_err = (r.get('extra') or {}).get('tool_result_is_error', False)
            if is_err:
                content = '[ERROR]\n' + content
            conversations.append({
                'from': 'tool',
                'value': f'<tool_response name="{tool_name}">\n{content}\n</tool_response>',
            })

    if not system_parts or not conversations:
        return None
    # Ensure last turn is gpt
    while conversations and conversations[-1]['from'] != 'gpt':
        conversations.pop()
    if not conversations:
        return None
    return {
        'system': '\n\n'.join(system_parts),
        'conversations': conversations,
        'meta': {
            'task_id': task_id,
            'model': model,
            'harness': harness,
            'run_dir': run_dir,
            'num_turns': len(conversations),
        },
    }


def parse_reward(path: Path):
    try:
        txt = path.read_text(encoding='utf-8', errors='replace').strip()
        return float(txt)
    except Exception:
        return None


def find_runs(root: Path):
    """Yield (task_dir, config_dict) for every leaf run directory containing agent/trajectory.json."""
    for bench_dir in sorted(root.iterdir()):
        if not bench_dir.is_dir():
            continue
        for ts_dir in sorted(bench_dir.iterdir()):
            if not ts_dir.is_dir():
                continue
            for task_dir in sorted(ts_dir.iterdir()):
                if not task_dir.is_dir():
                    continue
                traj = task_dir / 'agent' / 'trajectory.json'
                reward = task_dir / 'verifier' / 'reward.txt'
                if traj.exists() and reward.exists():
                    yield bench_dir.name, task_dir


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', default='first-round', help='root dir of benchmark runs')
    ap.add_argument('--output', default='sharegpt_out', help='output directory')
    ap.add_argument('--min-reward', type=float, default=1.0, help='keep runs with reward >= this')
    args = ap.parse_args()

    root = Path(args.input)
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    per_bench = {}
    kept, dropped_low_reward, dropped_bad_format, errors = 0, 0, 0, 0

    for bench_name, task_dir in find_runs(root):
        reward = parse_reward(task_dir / 'verifier' / 'reward.txt')
        if reward is None or reward < args.min_reward:
            dropped_low_reward += 1
            continue
        # Parse bench_name -> model + harness
        # e.g. 'binvulbench-mount-claude-opus-4-8-claudecode' -> model='claude-opus-4-8', harness='claudecode'
        m = re.match(r'binvulbench(?:-mount)?-(.+?)-(claudecode|codex|cc)$', bench_name)
        if m:
            model, harness = m.group(1), m.group(2)
        else:
            model, harness = bench_name, 'unknown'
        try:
            with open(task_dir / 'agent' / 'trajectory.json', 'r', encoding='utf-8') as f:
                traj = json.load(f)
        except Exception as e:
            print(f'[error] {task_dir}: {e}', file=sys.stderr)
            errors += 1
            continue
        task_id = task_dir.name.split('__')[0]
        rec = trajectory_to_sharegpt(traj, task_id, model, harness, str(task_dir.relative_to(root)))
        if rec is None:
            dropped_bad_format += 1
            continue
        per_bench.setdefault(bench_name, []).append(rec)
        kept += 1

    # Write per-bench files
    for bench_name, recs in sorted(per_bench.items()):
        fp = out_dir / f'{bench_name}.jsonl'
        with open(fp, 'w', encoding='utf-8') as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + '\n')
        print(f'wrote {len(recs):4d} -> {fp}')

    # Write merged file
    merged = out_dir / 'all.jsonl'
    total = 0
    with open(merged, 'w', encoding='utf-8') as f:
        for bench_name in sorted(per_bench):
            for r in per_bench[bench_name]:
                f.write(json.dumps(r, ensure_ascii=False) + '\n')
                total += 1
    print(f'wrote {total:4d} -> {merged}')

    print(f'\nsummary: kept={kept} dropped_low_reward={dropped_low_reward} '
          f'dropped_bad_format={dropped_bad_format} errors={errors}')


if __name__ == '__main__':
    main()
