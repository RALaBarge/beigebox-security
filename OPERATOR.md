# OPERATOR.md
# Project-specific instructions for the BeigeBox operator.
# Loaded automatically when the operator runs from this directory.

## Project overview

BeigeBox is a single-tenant LLM middleware proxy (FastAPI) that sits between any
client and any model backend. Every completion and tool call passes through it and
is recorded by wiretap. It exposes an OpenAI-compatible `/v1` endpoint and an MCP
server at `/mcp`. The operator skill (this repo) routes all its own LLM calls
through BeigeBox, so every operator session is fully observable.

## Stack

- Python 3.11+, FastAPI, httpx, SQLite (wiretap), pgvector (memory/document search)
- Ollama for local inference — default endpoint `http://localhost:11434`
- BeigeBox runs at `http://localhost:1337` (or `http://192.168.1.250:8001` in LXC)
- Config: `config.yaml` (main), `runtime_config.yaml` (runtime overrides)
- Packaging: `pyproject.toml`, lockfile `uv.lock`
- Tests: `pytest tests/`

## Key files

- `orientation.md` — hosts, services, git workflow; read this first for infrastructure context
- `V3.md` — what changed from v2 and why; read before touching deleted features
- `BEIGEBOX_IS_NOT.md` — constitution; new features must pass this before landing
- `config.yaml` — all feature flags and tool configuration
- `beigebox/main.py` — FastAPI app, route registration
- `beigebox/bootstrap.py` — startup sequence (DB init, tool registry, MCP server)
- `beigebox/mcp_server.py` — MCP handler, progressive tool disclosure, discover_tools
- `beigebox/tools/registry.py` — tool registration, reads config.yaml
- `beigebox/skills/operator/loop.py` — the agentic loop you are running inside right now
- `beigebox/tools/fs.py` — filesystem tools (read_file, write_file, edit_file, glob, search, directory_tree)
- `beigebox/tools/bash.py` — bash escape hatch, sandbox profiles
- `beigebox/tools/sandbox.py` — bwrap profile definitions (code-task, deploy-task, audit-task, open)

## Conventions

### Tool Protocol
Every tool is a class with:
- `description: str` — shown to the model; include JSON input format in the description
- `run(self, input_text: str) -> str` — receives a JSON string (or plain text), returns plain text
- Optional: `capability_tags: list[str]`, `capability_risk: str` (`"read"` or `"write"`)

Register new tools in `beigebox/tools/registry.py` under the appropriate config gate.
Add a config flag to `config.yaml` under `tools.<name>.enabled`.

### Adding a new tool (checklist)
1. Create `beigebox/tools/<name>.py` with a class following the Tool Protocol
2. Add `from beigebox.tools.<name> import MyTool` to `registry.py`
3. Add a registration block: `if tools_cfg.get("<name>", {}).get("enabled", False): self.tools["<name>"] = MyTool()`
4. Add `tools.<name>.enabled: false` to `config.yaml` (off by default unless trivially safe)
5. If the tool is read-only and has no external deps, default to `enabled: true`

### Path safety
All filesystem tools use `SafePath(user_input, base=working_dir)` which enforces
`resolve().relative_to(base)` — catches `..` traversal and symlink escapes.
Never skip SafePath for user-supplied paths.

### Working directory
The operator injects `working_dir` into every fs/bash tool call as a JSON field.
Tools read it from params and fall back to the contextvar, then `config.yaml`, then cwd.
When testing tools directly, pass `{"path": "...", "working_dir": "/path/to/project"}`.

### Config pattern
```python
from beigebox.config import get_config
cfg = get_config().get("tools", {}).get("my_tool", {})
```
`get_config()` is cached after first load. Changes to config.yaml require restart.

### Wiretap / observability
All tool calls are logged via `beigebox.logging.log_tool_call(...)`.
Completions are logged by the proxy middleware automatically.
To tail live: `python -m beigebox.cli tap`
To search past sessions: `python -m beigebox.cli sweep "<query>"`

### MCP progressive disclosure
`tools/list` only returns resident tools + `discover_tools`.
Resident set is defined in `mcp_server.py:_DEFAULT_RESIDENT_TOOLS`.
New tools go into extended (non-resident) by default — add to resident set only if
the model needs it in context on every call (keep resident set under ~12 tools).

### Sandbox profiles (bash tool)
| Profile | Network | FS | Use for |
|---|---|---|---|
| `code-task` | no | project rw | editing, testing |
| `deploy-task` | yes + ssh | project ro | deploy scripts, curl |
| `audit-task` | yes | all ro | reconnaissance, scanning |
| `open` | yes | rw | anything else |

## Always

- Run `pytest tests/ -x -q` after editing tool or registry code
- Check `python -c "import beigebox; print('ok')"` after editing `__init__.py` or `bootstrap.py`
- Use `SafePath` for any user-supplied file path
- Keep `description` strings accurate — the model reads them to decide what to pass
- Add new tools as disabled by default unless they're read-only with no external deps
- When editing `loop.py`, test streaming and non-streaming paths (pass `on_token=None` vs a callback)
- Check `BEIGEBOX_IS_NOT.md` before adding a feature that touches the proxy's trust boundary

## Never

- Push to `origin/main` (v2 frozen) — push to `security/main` for v3 work
- Use `--force`, `--no-verify`, or `--no-gpg-sign` on git commands
- Hit OpenRouter / Anthropic / OpenAI directly from project code — route through BeigeBox at `localhost:1337`
- Skip SafePath for filesystem operations
- Add a feature that requires trusting unvalidated LLM output at the proxy layer
- Automate connections to `hssh`/`hftp` (webspace) or `wssh`/`wftp` (Whatbox)
- Store secrets in code — use environment variables or `runtime_config.yaml` (gitignored)

## Preferred model

qwen2.5-coder:32b

## Notes

- BeigeBox in LXC: `http://192.168.1.250:8001`. On localhost: `http://localhost:1337`.
  The operator auto-detects from `config.yaml`; pass `--base-url` to override.
- `bwrap` (bubblewrap) may not work on kernels with unprivileged user namespaces
  disabled. The bash tool falls back gracefully — SafePath still enforces scoping.
- The `operator` and `bash` tools are disabled by default in `config.yaml`.
  Enable for a session: set `tools.operator.enabled: true` and `tools.bash.enabled: true`.
- Skills live in `beigebox/skills/`. Each skill directory should have a `SKILL.md`.
  Skills are exposed as MCP resources at `skill://<name>` via `resources/list`.
- The `discover_tools` MCP method returns full JSON schemas so the operator can add
  newly discovered tools to its active tool list mid-session.
- Memory/vector store tools require pgvector. If unavailable, they are skipped at
  registration time — the operator continues without memory orientation.
