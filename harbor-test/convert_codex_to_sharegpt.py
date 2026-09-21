# -*- coding: utf-8 -*-
"""
Codex ATIF trajectory -> LLaMA-Factory ShareGPT tool-use format.

Reads raw agent/trajectory.json files (NOT the intermediate all.jsonl) so we have
access to source_call_id for precise tool_call <-> observation pairing.

Output schema per record:
  {
    "system": "<clean minimal binary-analysis system prompt>",
    "tools":  "<JSON string of OpenAI-style function schemas>",  # LLaMA-Factory `tools` column
    "conversations": [
      {"from": "human",         "value": "<task markdown>"},
      {"from": "gpt",           "value": "<assistant reasoning text>"},          # optional pre-tool text
      {"from": "function_call", "value": "{\"name\": ..., \"arguments\": {...}}"},  # one per call
      ...
      {"from": "observation",   "value": "<tool result text>"},                  # one per call, in order
      ...
      {"from": "gpt",           "value": "<final assistant answer>"}
    ],
    "meta": {...}   # NOT fed to tokenizer
  }
"""
import json
import os
import re
import sys
import io
import argparse
import hashlib
from pathlib import Path
from collections import Counter, defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
OBS_HARD_LIMIT   = 4000   # absolute ceiling for any single observation
OBS_KEEP_HEAD    = 2400   # if truncated, keep this many head chars ...
OBS_KEEP_TAIL    = 1200   # ... and this many tail chars
MSG_HARD_LIMIT   = 30000  # ceiling for any single gpt / human message
MIN_OBS_KEPT     = 1      # sanity: every tool_call must have an obs

# A stable, minimal system prompt. Deliberately avoids Codex-specific paths,
# skills, sandbox/permission language.
AGENT_SYSTEM_PROMPT = (
    "You are an autonomous binary-analysis agent running in a Linux container. "
    "You are given a single target binary and a task description. Use shell "
    "commands, file inspection, and small Python scripts to understand the "
    "binary, design an input that exercises the requested behavior, and write "
    "the requested deliverable under /workspace/out. Report exactly what you "
    "observe; never fabricate results. Keep commands bounded and deterministic."
)

# OpenAI-style tool schemas. Sent via the `tools` column; LLaMA-Factory will
# inject them into the prompt template at training time.
TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "exec_command",
            "description": "Run a shell command in the workspace and return its stdout/stderr.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cmd":              {"type": "string", "description": "The command to execute."},
                    "workdir":          {"type": "string", "description": "Working directory for the command."},
                    "yield_time_ms":    {"type": "integer", "description": "How long to wait for output before returning, in milliseconds."},
                    "max_output_tokens": {"type": "integer", "description": "Maximum number of output tokens to return."}
                },
                "required": ["cmd"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "apply_patch",
            "description": "Apply a unified diff to create, modify, or delete files in the workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "input": {"type": "string", "description": "The patch text in the *** Begin Patch / *** End Patch format."}
                },
                "required": ["input"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "write_stdin",
            "description": "Write bytes to the stdin of a running process started with exec_command.",
            "parameters": {
                "type": "object",
                "properties": {
                    "session_id":  {"type": "integer", "description": "ID of the running exec session."},
                    "chars":       {"type": "string",  "description": "Bytes to write to stdin."},
                    "yield_time_ms": {"type": "integer"},
                    "max_output_tokens": {"type": "integer"}
                },
                "required": ["session_id", "chars"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write a file to disk at the given path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path":    {"type": "string"},
                    "content": {"type": "string"}
                },
                "required": ["path", "content"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file from disk.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                },
                "required": ["path"]
            }
        }
    }
]

# ---------------------------------------------------------------------------
# Codex runtime noise: patterns to strip from any text the model might see.
# These are lines/blocks that describe the Codex harness itself, not the task.
# ---------------------------------------------------------------------------
CODEX_NOISE_PATTERNS = [
    # <skills_instructions> ... </skills_instructions>
    (re.compile(r'<skills_instructions>.*?</skills_instructions>\s*', re.DOTALL), ''),
    # <permissions instructions> ... </permissions instructions>
    (re.compile(r'<permissions instructions>.*?</permissions instructions>\s*', re.DOTALL), ''),
    # <environment_context> ... </environment_context>
    (re.compile(r'<environment_context>.*?</environment_context>\s*', re.DOTALL), ''),
]

# ---------------------------------------------------------------------------
# Codex observation noise. These appear at the top of every exec_command result.
# We strip them and re-emit a minimal "exit code: N" header.
# ---------------------------------------------------------------------------
_OBS_HEADER_PATTERNS = [
    re.compile(r'^Chunk ID: [0-9a-f]+\s*\n', re.MULTILINE),
    re.compile(r'^Wall time: [0-9.]+ seconds\s*\n', re.MULTILINE),
    re.compile(r'^Original token count: \d+\s*\n', re.MULTILINE),
    re.compile(r'^Process exited with code (-?\d+)\s*\n', re.MULTILINE),
    re.compile(r'^Output:\s*\n', re.MULTILINE),
    # codex sometimes wraps the body in <stdout>...</stdout> or similar
    re.compile(r'^Warning: truncated output \(original token count: \d+\)\s*\n', re.MULTILINE),
    re.compile(r'^\.\.\. \d+ bytes omitted \.\.\.\s*\n', re.MULTILINE),
]

_EXIT_CODE_RE = re.compile(r'^Process exited with code (-?\d+)\s*$', re.MULTILINE)


def clean_codex_observation(raw: str) -> tuple[str, dict]:
    """
    Strip Codex-specific noise from one tool result body. Return (cleaned_text, stats).

    Keeps:
      - the actual command output (stdout/stderr text)
      - the exit code (re-emitted as a stable prefix so the model can learn
        to check it)
      - truncation marker if Codex itself truncated the output
    Drops:
      - Chunk ID, Wall time, Original token count lines
      - 'Output:' wrapper line
      - 'Warning: truncated output (original token count: N)' line
      - '... N bytes omitted ...' line (but we add our own '[output truncated]'
        marker if Codex omitted bytes)
    """
    stats = {'was_codex_truncated': False, 'bytes_omitted_by_codex': 0}
    if not isinstance(raw, str):
        raw = json.dumps(raw, ensure_ascii=False)

    text = raw

    # Detect Codex-side truncation before stripping the marker
    m = re.search(r'\.\.\. (\d+) bytes omitted \.\.\.', text)
    if m:
        stats['was_codex_truncated'] = True
        stats['bytes_omitted_by_codex'] = int(m.group(1))

    # Extract exit code before stripping
    m2 = _EXIT_CODE_RE.search(text)
    exit_code = m2.group(1) if m2 else None

    # Strip noise headers
    for pat in _OBS_HEADER_PATTERNS:
        text = pat.sub('', text)

    text = text.strip()

    # Re-emit a minimal stable header so the model can learn to read exit codes
    header_parts = []
    if exit_code is not None:
        header_parts.append(f'exit_code: {exit_code}')
    if stats['was_codex_truncated']:
        header_parts.append(f'[output truncated by harness: ~{stats["bytes_omitted_by_codex"]} bytes omitted]')
    if header_parts:
        text = '\n'.join(header_parts) + '\n' + text

    return text, stats


def truncate_middle(text: str, head: int, tail: int, marker_template: str = '\n... [{n} chars truncated] ...\n') -> str:
    if len(text) <= head + tail + 64:
        return text
    removed = len(text) - head - tail
    return text[:head] + marker_template.format(n=removed) + text[-tail:]


def truncate_observation(text: str) -> tuple[str, bool]:
    """Hard-cap one observation. Returns (new_text, was_truncated_by_us)."""
    if len(text) <= OBS_HARD_LIMIT:
        return text, False
    return truncate_middle(text, OBS_KEEP_HEAD, OBS_KEEP_TAIL), True


def truncate_message(text: str) -> str:
    if len(text) <= MSG_HARD_LIMIT:
        return text
    return truncate_middle(text, MSG_HARD_LIMIT // 2, MSG_HARD_LIMIT // 2)


# ---------------------------------------------------------------------------
# Task / system extraction
# ---------------------------------------------------------------------------
TASK_HEADER_RE = re.compile(r'(?m)^#\s+(?:PoC Generation Task|Task:)[^\n]*$')


def split_system_and_task(system_text: str) -> tuple[str, str]:
    """
    Split the codex-injected system blob into (clean_system_prompt, task_markdown).

    The codex system is structured as:
        <skills_instructions>...</skills_instructions>
        <permissions instructions>...</permissions instructions>
        <environment_context>...</environment_context>
        # PoC Generation Task   <-- real task starts here
        ...rest of task...
    We strip the three XML blocks, find the task header, and treat everything
    from that header onward as the user task.
    """
    cleaned = system_text
    for pat, rep in CODEX_NOISE_PATTERNS:
        cleaned = pat.sub(rep, cleaned)

    m = TASK_HEADER_RE.search(cleaned)
    if not m:
        # Fallback: look for any top-level markdown header that starts a long block
        m = re.search(r'(?m)^#\s+\S', cleaned)
    if not m:
        return '', ''   # signal failure

    task = cleaned[m.start():].strip()
    # Anything before the task header that isn't XML noise (rare) is dropped.
    return AGENT_SYSTEM_PROMPT, task


# ---------------------------------------------------------------------------
# Trajectory -> ShareGPT conversation
# ---------------------------------------------------------------------------
def convert_trajectory(traj: dict, task_id: str, model: str, harness: str, run_dir: str):
    stats = Counter()
    steps = traj.get('steps', [])
    if not steps:
        return None, {'error': 'no_steps'}

    # Pass 1: locate the codex system step and the task-containing user step.
    system_blob = ''
    task_text = None
    body_start_idx = 0
    for i, step in enumerate(steps):
        src = step.get('source')
        msg = step.get('message') or ''
        if src == 'system':
            system_blob += msg + '\n\n'
            body_start_idx = i + 1
            continue
        if src == 'user' and task_text is None:
            # The codex "user" turns include env_context and the actual task.
            # Combine them and let split_system_and_task extract the task.
            combined = (system_blob + msg).strip()
            sys_prompt, task = split_system_and_task(combined)
            if task:
                task_text = task
                body_start_idx = i + 1
                # Don't break: there may be a second user step that is ALSO
                # part of the task (rare). We instead continue and treat any
                # further 'user' steps as noise to drop.
                stats['user_steps_folded_into_task'] += 0  # placeholder
                continue
            else:
                # Not the task yet (e.g., pure env_context). Drop it.
                stats['user_steps_dropped_as_runtime_noise'] += 1
                body_start_idx = i + 1
                continue
        if src == 'user' and task_text is not None:
            # Subsequent user steps after we have the task: drop.
            stats['user_steps_dropped_after_task'] += 1
            body_start_idx = i + 1
            continue
        # First agent step: stop scanning
        break

    if not task_text:
        return None, {'error': 'no_task_extracted'}

    # Pass 2: walk the agent steps and emit messages.
    messages = [{'from': 'human', 'value': truncate_message(task_text)}]
    stats['human_messages'] = 1

    # Map tool_call_id -> function_name for pairing
    pending_calls: list[dict] = []  # calls in the current agent step

    for step in steps[body_start_idx:]:
        if step.get('source') != 'agent':
            continue

        msg = (step.get('message') or '').strip()
        tcs = step.get('tool_calls') or []

        # 1) Assistant reasoning text (if any) goes as a gpt turn.
        if msg:
            messages.append({'from': 'gpt', 'value': truncate_message(msg)})
            stats['gpt_messages'] += 1

        # 2) Each tool call becomes a function_call message.
        for tc in tcs:
            name = tc.get('function_name') or 'unknown'
            args = tc.get('arguments') or {}
            fc_value = json.dumps({'name': name, 'arguments': args},
                                  ensure_ascii=False)
            messages.append({'from': 'function_call', 'value': fc_value})
            stats['function_call_messages'] += 1
            pending_calls.append({'id': tc.get('tool_call_id'), 'name': name})

        # 3) Observations. Codex gives us a list of results, each tagged
        #    with source_call_id matching one tool_call_id. We pair them.
        obs_results = (step.get('observation') or {}).get('results') or []
        obs_by_id = {}
        for r in obs_results:
            cid = r.get('source_call_id')
            if cid:
                obs_by_id[cid] = r

        # Emit one observation per pending call, in the order the calls
        # were issued. If a call has no matching result (shouldn't happen
        # in well-formed data), emit a placeholder so roles stay balanced.
        for call in pending_calls:
            cid = call['id']
            r = obs_by_id.get(cid)
            if r is None:
                obs_text = '[no observation returned by harness]'
                stats['observations_missing_for_call'] += 1
            else:
                raw = r.get('content') or ''
                cleaned, cstats = clean_codex_observation(raw)
                if cstats['was_codex_truncated']:
                    stats['observations_codex_truncated'] += 1
                final_text, was_truncated = truncate_observation(cleaned)
                if was_truncated:
                    stats['observations_we_truncated'] += 1
                obs_text = final_text
                stats['observations_total_chars'] += len(obs_text)

            messages.append({'from': 'observation', 'value': obs_text})
            stats['observation_messages'] += 1

        pending_calls = []

    # Final structural checks
    if not any(m['from'] == 'function_call' for m in messages):
        return None, {'error': 'no_function_calls'}
    if messages[-1]['from'] not in ('gpt',):
        # Trim trailing non-gpt messages so the sample ends with a trainable
        # assistant turn. If the last thing is an observation, drop it (the
        # model never got to respond).
        while messages and messages[-1]['from'] != 'gpt':
            messages.pop()
            stats['trailing_non_gpt_dropped'] += 1
    if len(messages) < 3:
        return None, {'error': 'too_few_messages'}

    # Check role-sequence sanity:
    #   - observation must follow function_call or another observation
    #     (parallel tool calls return parallel observations)
    #   - function_call must follow human / gpt / observation / function_call
    #     (a single assistant turn may issue several parallel calls)
    for i, m in enumerate(messages):
        if m['from'] == 'observation':
            if i == 0 or messages[i-1]['from'] not in ('function_call', 'observation'):
                return None, {'error': f'orphan_observation_at_{i}'}
        if m['from'] == 'function_call':
            if i == 0 or messages[i-1]['from'] not in ('human', 'gpt', 'observation', 'function_call'):
                return None, {'error': f'bad_function_call_position_at_{i}'}

    record = {
        'system': AGENT_SYSTEM_PROMPT,
        'tools': json.dumps(TOOL_SCHEMAS, ensure_ascii=False),
        'conversations': messages,
        'meta': {
            'task_id': task_id,
            'teacher_model': model,
            'harness': harness,
            'run_dir': run_dir,
            'num_messages': len(messages),
            'num_function_calls': stats['function_call_messages'],
            # Traceability only — never sent to tokenizer
            'source_agent': (traj.get('agent') or {}).get('name'),
            'source_model': (traj.get('agent') or {}).get('model_name'),
            'session_id': traj.get('session_id'),
            'total_prompt_tokens': (traj.get('final_metrics') or {}).get('total_prompt_tokens'),
            'total_completion_tokens': (traj.get('final_metrics') or {}).get('total_completion_tokens'),
            'total_cost_usd': (traj.get('final_metrics') or {}).get('total_cost_usd'),
            'total_steps': (traj.get('final_metrics') or {}).get('total_steps'),
        }
    }
    stats['messages_total_chars'] = (
        len(record['system']) + len(record['tools']) +
        sum(len(m['value']) for m in messages)
    )
    return record, stats


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def find_codex_runs(root: Path):
    for bench_dir in sorted(root.iterdir()):
        if not bench_dir.is_dir():
            continue
        # Only process the codex harness dirs we care about for this task
        if 'codex' not in bench_dir.name:
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


def parse_reward(p: Path):
    try:
        return float(p.read_text(encoding='utf-8', errors='replace').strip())
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input',      default='first-round')
    ap.add_argument('--output',     default='sharegpt_clean')
    ap.add_argument('--bench',      default='binvulbench-mount-gpt-5.5-codex',
                    help='only convert this benchmark dir (default: gpt-5.5 codex)')
    ap.add_argument('--min-reward', type=float, default=1.0)
    ap.add_argument('--all-benches', action='store_true',
                    help='convert every codex bench, not just --bench')
    args = ap.parse_args()

    root = Path(args.input)
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    per_bench_records = defaultdict(list)
    global_stats = Counter()
    per_record_stats = []
    n_seen = n_reward_filtered = n_converted = n_failed = 0

    for bench_name, task_dir in find_codex_runs(root):
        if not args.all_benches and bench_name != args.bench:
            continue
        n_seen += 1
        reward = parse_reward(task_dir / 'verifier' / 'reward.txt')
        if reward is None or reward < args.min_reward:
            n_reward_filtered += 1
            continue

        # Parse bench_name -> model + harness
        m = re.match(r'binvulbench(?:-mount)?-(.+?)-(claudecode|codex|cc)$', bench_name)
        if m:
            model, harness = m.group(1), m.group(2)
        else:
            model, harness = bench_name, 'codex'

        try:
            with open(task_dir / 'agent' / 'trajectory.json', 'r', encoding='utf-8') as f:
                traj = json.load(f)
        except Exception as e:
            print(f'[error] {task_dir}: {e}', file=sys.stderr)
            n_failed += 1
            continue

        task_id = task_dir.name.split('__')[0]
        rec, stats = convert_trajectory(
            traj, task_id, model, harness,
            str(task_dir.relative_to(root))
        )
        if rec is None:
            n_failed += 1
            print(f'[drop] {task_dir.name}: {stats}', file=sys.stderr)
            continue

        per_bench_records[bench_name].append(rec)
        per_record_stats.append({
            'task_id': task_id,
            'num_messages': rec['meta']['num_messages'],
            'num_function_calls': rec['meta']['num_function_calls'],
            'messages_total_chars': stats['messages_total_chars'],
            'observations_codex_truncated': stats.get('observations_codex_truncated', 0),
            'observations_we_truncated': stats.get('observations_we_truncated', 0),
            'observations_total_chars': stats.get('observations_total_chars', 0),
        })
        for k, v in stats.items():
            global_stats[k] += v
        n_converted += 1

    # Write output
    out_files = []
    for bench_name, recs in sorted(per_bench_records.items()):
        fp = out_dir / f'{bench_name}.sharegpt.jsonl'
        with open(fp, 'w', encoding='utf-8') as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + '\n')
        out_files.append((fp, len(recs)))
        print(f'wrote {len(recs):4d} -> {fp}')

    merged = out_dir / 'all.sharegpt.jsonl'
    total = 0
    with open(merged, 'w', encoding='utf-8') as f:
        for bench_name in sorted(per_bench_records):
            for r in per_bench_records[bench_name]:
                f.write(json.dumps(r, ensure_ascii=False) + '\n')
                total += 1
    print(f'wrote {total:4d} -> {merged}')

    # ------------------------------------------------------------------
    # Stats report
    # ------------------------------------------------------------------
    print('\n=== conversion summary ===')
    print(f'  runs seen                : {n_seen}')
    print(f'  dropped (reward < {args.min_reward:g}): {n_reward_filtered}')
    print(f'  dropped (conversion err) : {n_failed}')
    print(f'  converted                : {n_converted}')

    if per_record_stats:
        msgs  = [s['num_messages'] for s in per_record_stats]
        fcs   = [s['num_function_calls'] for s in per_record_stats]
        chars = [s['messages_total_chars'] for s in per_record_stats]
        obs_chars = [s['observations_total_chars'] for s in per_record_stats]
        codex_trunc = sum(s['observations_codex_truncated'] for s in per_record_stats)
        we_trunc    = sum(s['observations_we_truncated'] for s in per_record_stats)

        def mm(label, xs):
            xs = sorted(xs)
            n = len(xs)
            med = xs[n//2] if n % 2 else (xs[n//2 - 1] + xs[n//2]) // 2
            p90 = xs[int(0.9 * (n - 1))]
            print(f'  {label:26s}: min={xs[0]:6d} med={med:6d} p90={p90:6d} max={xs[-1]:6d}')

        print('\n=== per-record stats ===')
        mm('messages per sample', msgs)
        mm('function calls per sample', fcs)
        mm('total chars per sample', chars)
        mm('observation chars per sample', obs_chars)
        print(f'  obs truncated by codex   : {codex_trunc}')
        print(f'  obs truncated by us      : {we_trunc}')

    print('\n=== global counters ===')
    for k, v in sorted(global_stats.items()):
        print(f'  {k:35s}: {v}')

    # Write stats sidecar
    stats_fp = out_dir / 'conversion_stats.json'
    with open(stats_fp, 'w', encoding='utf-8') as f:
        json.dump({
            'args': vars(args),
            'runs_seen': n_seen,
            'dropped_reward': n_reward_filtered,
            'dropped_error': n_failed,
            'converted': n_converted,
            'global_stats': dict(global_stats),
            'per_record': per_record_stats,
        }, f, ensure_ascii=False, indent=2)
    print(f'\nstats written to {stats_fp}')


if __name__ == '__main__':
    main()
