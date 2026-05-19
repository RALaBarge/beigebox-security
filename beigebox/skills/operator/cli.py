"""CLI for the operator skill."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys


_OPERATOR_MD_TEMPLATE = """\
# OPERATOR.md
# Project-specific instructions for the BeigeBox operator.
# Loaded automatically when you run the operator from this directory.
# Equivalent to CLAUDE.md — operator falls back to CLAUDE.md if this file is absent.

## Project overview
<!-- What this project does, in 2-3 sentences. -->

## Stack
<!-- Languages, frameworks, key dependencies. -->

## Conventions
<!-- Naming, structure, patterns the operator should follow or avoid. -->

## Key files
<!-- Files the operator should read first to orient itself. -->
<!-- Example: -->
<!-- - README.md — project overview -->
<!-- - src/main.py — entry point -->
<!-- - docs/architecture.md — system design -->

## Always
<!-- Things the operator must always do. -->
<!-- Example: run tests after editing, use the project's linter, write to workspace/out/ -->

## Never
<!-- Things the operator must never do. -->
<!-- Example: push to main, delete migration files, modify .env -->

## Preferred model
<!-- Leave blank to use BeigeBox default. -->
<!-- Example: qwen2.5-coder:32b -->

## Notes
<!-- Anything else relevant: known quirks, team preferences, external systems. -->
"""


def _cmd_init(args: argparse.Namespace) -> int:
    from pathlib import Path
    wd = Path(args.working_dir).resolve() if args.working_dir else Path.cwd()
    target = wd / "OPERATOR.md"
    if target.exists() and not args.force:
        print(f"OPERATOR.md already exists at {target}. Use --force to overwrite.", file=sys.stderr)
        return 1
    target.write_text(_OPERATOR_MD_TEMPLATE, encoding="utf-8")
    print(f"Created {target}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    task = args.task
    if not task:
        if sys.stdin.isatty():
            print("Provide a task argument or pipe via stdin.", file=sys.stderr)
            return 1
        task = sys.stdin.read().strip()
    if not task:
        print("Task is empty.", file=sys.stderr)
        return 1

    from beigebox.skills.operator.loop import run

    on_token = None
    if not args.no_stream and not args.as_json:
        def on_token(text: str) -> None:
            print(text, end="", flush=True)

    result = asyncio.run(run(
        task=task,
        model=args.model,
        working_dir=args.working_dir,
        profile=args.profile,
        max_turns=args.max_turns,
        system_prompt=args.system,
        base_url=args.base_url,
        api_key=args.api_key,
        extra_context=args.context,
        on_token=on_token,
    ))

    if args.as_json:
        print(json.dumps(result, indent=2))
    elif args.no_stream:
        # Non-streaming: print answer now (streaming already printed tokens)
        print(result["answer"])

    if result["tool_calls"] and not args.as_json:
        print(
            f"\n[{result['turns']} turns · "
            f"{len(result['tool_calls'])} tool calls · "
            f"session {result['session_id']}]",
            file=sys.stderr,
        )

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="python -m beigebox.skills.operator",
        description="BeigeBox operator — agentic task loop with full wiretap observability.",
    )
    subparsers = parser.add_subparsers(dest="subcommand")

    # --- init subcommand ---
    p_init = subparsers.add_parser("init", help="Generate OPERATOR.md template in working dir.")
    p_init.add_argument("--working-dir", default="", help="Directory to write OPERATOR.md into.")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing OPERATOR.md.")

    # --- run (default, no subcommand) ---
    # These args apply when no subcommand is given
    parser.add_argument("task", nargs="?", help="Task description. Reads from stdin if omitted.")
    parser.add_argument("--model", default="", help="Model name (BeigeBox routes it).")
    parser.add_argument("--working-dir", default="", help="Project root for filesystem tools.")
    parser.add_argument("--profile", default="code-task",
                        choices=("code-task", "deploy-task", "audit-task", "open"),
                        help="Sandbox profile for bash tool calls.")
    parser.add_argument("--max-turns", type=int, default=30, help="Hard turn limit.")
    parser.add_argument("--base-url", default="", help="BeigeBox base URL.")
    parser.add_argument("--api-key", default="none", help="BeigeBox API key.")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="Print full result JSON (disables streaming).")
    parser.add_argument("--no-stream", action="store_true",
                        help="Disable streaming output (wait for full response).")
    parser.add_argument("--system", default="", help="Override system prompt.")
    parser.add_argument("--context", default="", help="Extra context appended to system prompt.")

    args = parser.parse_args()

    if args.subcommand == "init":
        return _cmd_init(args)

    return _cmd_run(args)
