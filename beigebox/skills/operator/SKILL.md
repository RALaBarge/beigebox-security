---
name: operator
version: 1
description: Agentic task loop. Routes all completions through BeigeBox /v1/chat/completions and all tool calls through /mcp so wiretap captures the full session. Use this to drive multi-step tasks with file access, bash execution, and any registered BeigeBox tool.
---

# operator

`python -m beigebox.skills.operator <task>` — run an agentic task loop through BeigeBox.

## When to invoke

- Multi-step tasks requiring tool use (file read/write, bash, search, web)
- Offline work using local models via Ollama
- Any task where you want full wiretap observability over completions AND tool calls

## Usage

```bash
# Basic task
python -m beigebox.skills.operator "find all TODO comments in the codebase and summarize them"

# With model and project root
python -m beigebox.skills.operator "add type hints to auth.py" \
  --model qwen2.5-coder:7b \
  --working-dir /my/project \
  --profile code-task

# Network-capable task
python -m beigebox.skills.operator "check if port 8080 is open and what's listening" \
  --profile open

# Deployment task (network + ssh)
python -m beigebox.skills.operator "rsync build/ to staging" \
  --profile deploy-task

# Full JSON output (includes session_id for wiretap lookup)
python -m beigebox.skills.operator "list Python files" --json

# Pipe task from stdin
echo "summarize workspace/in/report.md" | python -m beigebox.skills.operator
```

## Python API

```python
import asyncio
from beigebox.skills.operator import run

result = asyncio.run(run(
    task="find all TODO comments in the codebase",
    model="qwen2.5-coder:7b",
    working_dir="/my/project",
    profile="code-task",
    max_turns=20,
))

print(result["answer"])
# result["session_id"]  → look up in wiretap
# result["tool_calls"]  → [{turn, tool, input, result}, ...]
# result["turns"]       → number of turns used
```

## Sandbox profiles

| Profile | Network | Filesystem | Use for |
|---|---|---|---|
| `code-task` | No | Project dir rw | Default. Editing, analysis, tests. |
| `deploy-task` | Yes | Project dir rw, ssh ro | Git push, rsync, deploy scripts. |
| `audit-task` | Yes | Project dir read-only | Scanning, recon, read-only analysis. |
| `open` | Yes | Project dir rw | When other profiles are too restrictive. |

Set `tools.bash.ssh_dir` in config.yaml to provide an SSH key dir for deploy-task.

## Wiretap correlation

Every request in a session carries the same `conversation_id` (the session UUID).
In wiretap, filter by that ID to see the full trace: completions, tool calls, results.

```bash
python -m beigebox.cli tap --session <session_id>
# or
python -m beigebox.cli sweep "operator session <session_id>"
```

## Architecture

```
model call  →  BeigeBox /v1/chat/completions  →  wiretap
tool call   →  BeigeBox /mcp/tools/call       →  tool registry  →  wiretap
                                                    └─ read_file, write_file, edit_file
                                                    └─ glob, search, directory_tree
                                                    └─ bash (escape hatch)
                                                    └─ web_search, memory, ...
```

All traffic goes through BeigeBox. The operator has no direct tool execution.

## Requirements

- BeigeBox running at localhost:1337 (or configured port)
- `httpx` (already a beigebox dependency)
- For bash tool: `bwrap` installed for sandbox profiles (graceful fallback without it)
