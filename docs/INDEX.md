# Documentation Index — BeigeBox V3

This is the V3 (`beigebox-security`) documentation. V2 docs live in the [`RALaBarge/beigebox`](https://github.com/RALaBarge/beigebox) repo.

For the v2→v3 deletion list and reasoning, read **[../V3.md](../V3.md)** first. For the standing "no" list (single-tenant, not an inference engine, not an agent harness, …), read **[../BEIGEBOX_IS_NOT.md](../BEIGEBOX_IS_NOT.md)**.

---

## Getting Started

1. **[Deployment](deployment.md)** — Install + run BeigeBox (LXC native, Docker Compose, Systemd)
2. **[Architecture](architecture.md)** — Request pipeline + subsystem map
3. **[Configuration](configuration.md)** — `config.yaml`, `runtime_config.yaml`, feature flags

## Routing & Backends

- **[Routing & Backends](routing.md)** — Per-model provider selection, latency-aware ordering, retry-with-backoff
- **[Authentication](authentication.md)** — Multi-key registry, admin gate, ACLs, agentauth keychain

## Integration

- **[Agents](agents.md)** — How external MCP clients (Claude Code, jcode, custom SDK) drive BeigeBox now that the in-tree agent loop is gone
- **[Tools & MCP](tools.md)** — Bundled tools, MCP server (`/mcp`), opt-in Pen/Sec MCP (`/pen-mcp`), CDP, plugins
- **[API Reference](api-reference.md)** — HTTP endpoints + request/response formats
- **[CLI](cli.md)** — `bb sweep`, `bb tap`, `bb ring`, `bb flash`, `bb dump`, `bb bench`, …

## Operations

- **[Observability](observability.md)** — Wiretap event types, metrics, debugging
- **[Observability Coverage](observability-coverage.md)** — what's emitted, what's a gap, the rubric for adding new events
- **[Security](security.md)** — Defenses, threat model, supply chain hardening

## Skills

Importable async pipelines under `beigebox/skills/`. Each has its own `SKILL.md`.

- **`fuzz`** ([SKILL.md](../beigebox/skills/fuzz/SKILL.md)) — pure-Python coverage-blind mutation fuzzer; risk-scored discovery, adaptive time budget, package-aware harness loader, `garlicpress`-shape findings
- **`fanout`** ([SKILL.md](../beigebox/skills/fanout/SKILL.md)) — list-in → N parallel OpenAI-compat calls + optional reduce
- **`host-audit`** ([SKILL.md](../beigebox/skills/host-audit/SKILL.md)) — single-host audit of running containers/VMs/listening services
- **`services-inventory`** ([SKILL.md](../beigebox/skills/services-inventory/SKILL.md)) — same audit fleet-wide via SSH
- **`host-notes`** ([SKILL.md](../beigebox/skills/host-notes/SKILL.md)) — per-host operator notes (gitignored)
- **`grill-with-docs`** ([SKILL.md](../beigebox/skills/grill-with-docs/SKILL.md)) — doc-driven interrogation
- **`improve-codebase-architecture`** ([SKILL.md](../beigebox/skills/improve-codebase-architecture/SKILL.md)) — architecture-review pipeline
- **`diagnose`**, **`make-skill`**, **`make-tool`** — meta-skills

### Portfolio

- **[fuzz + static six-repo validation](portfolio/fuzz-static-validation.md)** — methodology, results, notable findings

## Design History

- **[Grok Reviews — 2026-05-01 v3 demolition](grok_reviews_2026_05_01.md)** — pre-merge critiques (x-ai/grok-4 + grok-4.3) for the SQLiteStore demolition + capture-pipeline + log-events consolidation + routers split. Captures design rationale for the 35 commits between `36ab408` and `a46825f`.
- **[../V3.md](../V3.md)** — full v2→v3 changelog (deletions, additions, surviving rationale)

---

## By Use Case

| I want to… | Go to |
|---|---|
| Run BeigeBox locally | [Deployment](deployment.md) |
| Understand request flow | [Architecture](architecture.md) |
| Add a backend or change routing | [Routing](routing.md) |
| Add API keys / restrict access | [Authentication](authentication.md) |
| Drive BeigeBox from an external agent client | [Agents](agents.md) |
| Add a custom tool | [Tools](tools.md) + [Tool Protocol](../beigebox/tools/base.py) |
| Harden for production | [Security](security.md) |
| Debug a problem | [Observability](observability.md) |
| Audit the UI for dead surfaces | [`/mnt/media/beigebox-data/crawl_ui.py`](../V3.md#open-h-batch-items-still-queued) (CDP crawler) |

---

## Files Referenced

### Core Configuration

- `config.yaml` — Bake-time config (backends, routing, storage paths, security defenses, features). Supports `${VAR}` env interpolation.
- `data/runtime_config.yaml` — Hot-reload session overrides (`force_route`, `tools_disabled`, etc.)
- `docker/config.yaml` — Reference template (the v2 docker setup uses this; v3 LXC native uses `config.yaml` at the project root)

### Source Code

- `beigebox/main.py` — FastAPI app + lifespan; thin after v3 routers/middleware/bootstrap extraction
- `beigebox/proxy/` — Request pipeline package: `core.py` orchestrator, `request_helpers.py`, `body_pipeline.py`, `model_listing.py`, `request_inspector.py`, `__init__.py` re-exports
- `beigebox/routers/` — Per-area route handlers (auth, openai, security, workspace, analytics, tools, config, misc)
- `beigebox/config.py` — Config loader with `${VAR}` resolution
- `beigebox/backends/router.py` — `MultiBackendRouter` engine
- `beigebox/cache.py` — `ToolResultCache` (SemanticCache + EmbeddingCache deleted in v3)
- `beigebox/capture.py` — Single chokepoint for chat-completion telemetry; `CaptureFanout` → ConversationRepo + WireLog + VectorStore
- `beigebox/storage/repos/` — Five repos (`ApiKeyRepo`, `ConversationRepo`, `QuarantineRepo`, `UserRepo`, `WireEventRepo`) on `BaseDB` shim
- `beigebox/storage/backends/{base,postgres,memory}.py` — Vector backend factory (chromadb removed in v3)
- `beigebox/tools/base.py` — `Tool` Protocol contract
- `beigebox/tools/registry.py` — `ToolRegistry` with runtime Protocol sanity check
- `beigebox/web/index.html` — Web UI (no build step; ~8.9k lines after v3 cleanup)

### Observability & Security

- `beigebox/security/` — `enhanced_injection_guard`, `rag_content_scanner`, `anomaly_detector`, `extraction_detector`, `honeypot_manager`
- `beigebox/security_mcp/` — Pen/Sec MCP wrapper for 53 *nix offensive-security tools
- `beigebox/observability/` — Poisoning metrics, log events
- `requirements.lock` — Hash-locked Python deps
- `scripts/security-scan.sh` — pip-audit + bandit + semgrep + gitleaks + trivy

---

## Common Workflows

### Benchmark backend speed

```bash
.venv/bin/python -m beigebox.cli bench --model llama3.1:8b --num-runs 5
```

See [CLI](cli.md#benchmarking).

### Probe backends

```bash
.venv/bin/python -m beigebox.cli ring
```

Returns one line per backend with reachability + latency.

### Tail the wiretap

```bash
.venv/bin/python -m beigebox.cli tap                    # live tail
.venv/bin/python -m beigebox.cli tap --filter route     # filter event type
```

See [Observability](observability.md).

### Search past conversations

```bash
.venv/bin/python -m beigebox.cli sweep "what did I ask about postgres last week"
```

Hits the postgres+pgvector store.

### Update dependencies

```bash
# Edit requirements.txt, then:
uv pip compile requirements.txt --generate-hashes --output-file requirements.lock
```

See [Security: Hash Locking](security.md#python-dependencies--hash-locked).

### Scan for CVEs

```bash
./scripts/security-scan.sh           # full
./scripts/security-scan.sh --quick   # python-only (pip-audit + bandit + semgrep)
```

---

## Key Concepts

| Term | Definition |
|---|---|
| **Backend** | Inference provider (OpenRouter, Ollama, mlx-lm, OpenAI-compat) |
| **MultiBackendRouter** | Picks a backend for the request's `model` by priority + `allowed_models`; latency-aware demotion |
| **Normalizer seam** | Request + response normalizers translate any backend's quirks to/from OpenAI shape, with a transform-log on the wiretap |
| **MCP** | Model Context Protocol — how external agent clients drive BeigeBox tools (`/mcp` for general, `/pen-mcp` for offensive-security) |
| **Tool Protocol** | Runtime-checkable contract every registered tool must satisfy: `description: str` + `run(input_text) -> str \| dict`. See [base.py](../beigebox/tools/base.py). |
| **Tap / Wiretap** | Unified event log (dual-write SQLite + JSONL); query via `bb tap` |
| **Hook** | Event-driven custom code via `HookManager` — runs in pre/post-request priority order, can mutate body or short-circuit via `_beigebox_block` |
| **Memory** | Postgres+pgvector vector store (chromadb removed in v3); exposed via `bb sweep` + the `memory` MCP tool |
| **Capture pipeline** | Single chokepoint (`beigebox/capture.py`); `CaptureFanout` fans one captured turn to ConversationRepo + WireLog + VectorStore |

---

## What's NOT in v3 (deliberately)

If you're looking for one of these, read [../V3.md](../V3.md) for the deletion rationale and migration path:

- **Operator class / `operator/run` MCP schema** — agent loops live in the driving client now
- **Harness / Wiggam / Ralph / Orchestrate** — same reason; agent panels deleted from UI
- **Z-commands (`z: search`, `z: code`, …)** — modern models route their own queries
- **Decision LLM + Embedding Classifier** — same reason; tier-2 + tier-4 routers gone
- **Council + Voice subtabs** — moved to "external client owns this" stance
- **`SemanticCache`** — low hit rate, real bug source; only `ToolResultCache` survives
- **`SQLiteStore`** monolith — replaced by 5 focused repos on `BaseDB` shim
- **`chromadb` vector backend** — postgres+pgvector only
- **`SimplePasswordAuth`** — multi-key registry only
- **`mcp_parameter_validator`** — was dead code; live validator at `tools/validation.py`
- **`python_interpreter` + `workspace_file` tools** — driving client owns code/FS
- **AMF mesh subsystem** — Go agent fabric, no remaining consumers
- **Querystring auth (`?api_key=`)** — Bearer token only

---

## Defense-in-depth

V3 assumes supply chain compromise is inevitable, not a rare edge case.

**Three layers:**

1. **Prevention** — Hash-locked deps, pinned images, CVE scanning
2. **Containment** — Read-only root, network segmentation, capability drop, unprivileged user
3. **Detection** — Wiretap, metrics, git hooks

Plus the in-app AI defenses (injection guard, RAG content scanner, anomaly detector, extraction detector, honeypot manager) — observe-only by default, configurable to block.

See [Security](security.md) for the full threat model.

---

## Quick Links

- **This repo (V3)**: [RALaBarge/beigebox-security](https://github.com/RALaBarge/beigebox-security)
- **V2 (frozen)**: [RALaBarge/beigebox](https://github.com/RALaBarge/beigebox)
- **Issues**: [GitHub Issues](https://github.com/RALaBarge/beigebox-security/issues)
- **Main README**: [../README.md](../README.md)
- **V3 changelog**: [../V3.md](../V3.md)
- **Constitution**: [../BEIGEBOX_IS_NOT.md](../BEIGEBOX_IS_NOT.md)
- **License**: [../LICENSE.md](../LICENSE.md) (AGPL-3.0 + Commercial)
