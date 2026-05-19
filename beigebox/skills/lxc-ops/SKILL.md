---
name: lxc-ops
version: 1
description: Use when the user wants to deploy / test / restart / debug BeigeBox running in the `beigebox` LXC on the debian host — i.e. "sync source to the LXC", "test in the LXC venv", "restart beigebox", "spawn a long-running task in the LXC", "we have root pane 1", "run pytest in beigebox", "deploy this branch", "what's the LXC's IP". Captures the operational pattern Claude actually uses to drive that LXC from a non-root agent on the debian host. Skip this skill for single-machine / non-LXC tasks; skip for the pop-os Docker BeigeBox.
---

# lxc-ops

Operational playbook for driving the `beigebox` LXC on debian. Claude on debian runs as the `ryan` user with no passwordless sudo, but the operator typically attaches a **root tmux pane** (pane 0:0.1 in the canonical setup). Everything below assumes that pane is available.

Treat this skill as the runbook for "how do I reach the BeigeBox process the user actually depends on."

## When to invoke

- User says "the LXC", "in beigebox", "deploy to the LXC", "test in the LXC", "restart beigebox", "sync to the LXC".
- A task needs Python deps from BeigeBox's installed venv (1,400-test pytest suite, `beigebox.cli`, `beigebox.skills.*`).
- A task needs to write under `/opt/beigebox`, `/etc/beigebox`, or `/var/lib/lxc/beigebox/...`.
- A task fires `python -m beigebox.skills.fanout` or any other module-import-time-heavy entrypoint; running them on bare host as `ryan` will fail because `beigebox` isn't installed on the host.

## Skip this skill if

- Working purely against the source tree at `/mnt/media/ai-stack/beigebox-security/` and not deploying.
- The BeigeBox involved is the **pop-os Docker container** (`docker compose` lives there, no LXC).
- The user is on the mac (`assh`) and wants to run in their local Colima image, not on debian.

## Layout — what's where

| | host (debian, user `ryan`) | LXC (root, hostname `beigebox`) |
|---|---|---|
| Source tree | `/mnt/media/ai-stack/beigebox-security/` (NFS-shared, gitignored `config.yaml`) | `/opt/beigebox/` — fresh `git clone` from `RALaBarge/beigebox-security` |
| venv | absent (intentionally) | `/opt/beigebox/.venv/bin/python` |
| Service | n/a | `systemctl {status,restart,stop} beigebox.service` |
| Env file | n/a | `/etc/beigebox/env` (mode 600, root) — `OPENROUTER_API_KEY=…`, `BEIGEBOX_ALLOW_EMPTY_AUTH=1` |
| Logs | n/a | `journalctl -u beigebox.service` |
| LXC config | `/var/lib/lxc/beigebox/config` (root-only) | `/etc/netplan/10-lxc.yaml` (inside) |
| LXC IP | reachable from host at `192.168.1.250:8001` | binds `0.0.0.0:8001` |
| Postgres | n/a | localhost:5432, db `beigebox`, user `postgres`/`postgres`, pgvector installed |

The LXC's "host filesystem view from outside" is at `/var/lib/lxc/beigebox/rootfs/<path-inside-lxc>` — accessible only as root, useful for editing files without entering the LXC.

## Driving the LXC from Claude

Claude (pane 0:0.0) is `ryan` and **cannot `lxc-attach`** — `lxc-attach` requires root and the unprivileged invocation returns "Connection refused / Failed to get init pid". Use the operator's root pane (pane 0:0.1) for anything that needs root.

### Send-and-capture pattern

```bash
tmux send-keys -t 0:0.1 'lxc-attach -n beigebox -- <command>' Enter
sleep N                               # ← only for short commands; see below
tmux capture-pane -t 0:0.1 -p         # read most-recent screen
tmux capture-pane -t 0:0.1 -p -S -200 # read with scrollback
```

`send-keys` returns *immediately* — the command runs asynchronously in the pane. For anything longer than ~3 seconds, prefer the long-running pattern below over `sleep`.

### Long-running tasks: `systemd-run`, not `nohup &`

A `nohup … &` launched via `lxc-attach` dies when the attach session terminates. Use a **transient systemd unit** instead:

```bash
tmux send-keys -t 0:0.1 \
  'lxc-attach -n beigebox -- systemd-run --unit=my-task --working-directory=/opt/beigebox /bin/bash /opt/beigebox/run-thing.sh' \
  Enter
```

Then poll `systemctl is-active my-task` until it's `inactive`. `journalctl -u my-task` gives full output.

To wait for it without polling in your own context, spawn a host-side watcher (root pane writes a sentinel when the unit goes inactive, you `until [ -f /tmp/sentinel ]; do sleep 60; done` from your own context with `run_in_background: true`).

### Capturing output reliably

Tmux only retains the last screen + scrollback (default ~2000 lines). For long pytest runs:

1. Have the in-LXC command tee its output to a file: `… 2>&1 | tee /opt/beigebox/run.log`.
2. After the task finishes (sentinel fires), read the file via `/var/lib/lxc/beigebox/rootfs/opt/beigebox/run.log` from the host root pane.

Don't use `until grep -q "===END==="` patterns that match on the *typed* command text — the sentinel must be unique enough that the typed command's echoing won't match it. (Yes, this happens.)

## Common operations

### Sync source → LXC (without nuking deployed config)

`config.yaml` at the project root is gitignored and the LXC's copy may carry deployment-specific edits (e.g. `auth.enabled: false`). **Skip it from the rsync.**

```bash
SRC=/mnt/media/ai-stack/beigebox-security
DST=/var/lib/lxc/beigebox/rootfs/opt/beigebox
rsync -a --exclude=__pycache__ --exclude=.venv --exclude=.git \
      --exclude='data/' --exclude='logs/' --exclude='workspace/' \
      --exclude='*.json' --exclude='grok-*' --exclude='trinity-*' \
      --exclude='qwen-*' --exclude='security-fix-plan-*' \
      "$SRC/beigebox/" "$DST/beigebox/"
rsync -a --exclude=__pycache__ "$SRC/plugins/" "$DST/plugins/"
rsync -a --exclude=__pycache__ "$SRC/tests/" "$DST/tests/"
cp "$SRC/BEIGEBOX_IS_NOT.md" "$DST/BEIGEBOX_IS_NOT.md"
cp "$SRC/docker/config.yaml" "$DST/docker/config.yaml"
```

### Run pytest in the LXC venv

```bash
lxc-attach -n beigebox -- bash -c \
  'cd /opt/beigebox && /opt/beigebox/.venv/bin/python -m pytest tests/ 2>&1 | tail -30'
```

Pytest is **not** in `requirements.lock` — install it once with
`/opt/beigebox/.venv/bin/pip install pytest pytest-asyncio` if missing.

### Restart the service after a code change

```bash
lxc-attach -n beigebox -- systemctl restart beigebox.service
lxc-attach -n beigebox -- systemctl is-active beigebox.service
lxc-attach -n beigebox -- journalctl -u beigebox.service --no-pager -n 30
```

### Reach the running BeigeBox from outside

- LAN: `http://192.168.1.250:8001/v1/...`
- From the host: same.
- From inside the LXC: `http://localhost:8001/...`
- Tailscale: `http://100.122.135.12:8001/...` *if* `tailscaled` is up inside the LXC. It's frequently offline; check `tailscale status` from the host.

### Drop a file into the LXC without entering it

The host root pane can write directly to `/var/lib/lxc/beigebox/rootfs/<lxc-path>`. Useful for staging scripts, env files, or config edits.

```bash
# Host root pane — appears inside LXC at /tmp/foo.sh
cat > /var/lib/lxc/beigebox/rootfs/tmp/foo.sh <<'EOF'
#!/bin/bash
…
EOF
chmod +x /var/lib/lxc/beigebox/rootfs/tmp/foo.sh
lxc-attach -n beigebox -- bash /tmp/foo.sh
```

### Read OPENROUTER_API_KEY from the running process

If the operator has the key in their login shell but not in the systemd env, the running BeigeBox process might be missing it. Verify by reading the process environ from the host root pane:

```bash
tr '\0' '\n' < /proc/$(pgrep -f beigebox.main)/environ | grep -E '^OPENROUTER_API_KEY=' | wc -c
```

If empty, the env file isn't loaded; check `/etc/beigebox/env` and `EnvironmentFile=` in the systemd unit.

## Networking gotchas

- The LXC attaches via macvlan/bridge to the LAN; it has its own DHCP-or-static address on `192.168.1.0/24`, **not** an `lxcbr0` 10.0.3.x address.
- Host-side static IP is set in `/var/lib/lxc/beigebox/config` as `lxc.net.0.ipv4.address = 192.168.1.250/24`.
- Inside the LXC, `/etc/netplan/10-lxc.yaml` controls eth0. **If both static and DHCP are on, the LXC ends up with two IPs** and one of them often collides with another LXC. Set `dhcp4: false` in netplan.
- `netplan apply` inside the LXC fails with "udevadm control --reload" — workaround: `ip addr del <duplicate>/24 dev eth0` for the immediate fix, then `netplan generate && networkctl reload` for a clean re-apply on next boot.

## OpenRouter via BeigeBox

All external LLM calls go through `http://192.168.1.250:8001/v1` (OpenAI-compatible). The proxy uses `OPENROUTER_API_KEY` from `/etc/beigebox/env`.

```bash
# Live model catalog (run inside LXC):
lxc-attach -n beigebox -- bash -c \
  'cd /opt/beigebox && /opt/beigebox/.venv/bin/python -m beigebox.cli models \
   --url http://localhost:8001 --search grok'

# A direct chat completion (smoke test):
curl -sS http://192.168.1.250:8001/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"ping"}],"max_tokens":5}'
```

## Fanout for parallel LLM work

`beigebox/skills/fanout/SKILL.md` is the right tool when you need many parallel LLM calls — code review, verification, batch summarization. Run via `/opt/beigebox/.venv/bin/python -m beigebox.skills.fanout` inside the LXC.

`fanout` defaults to `http://localhost:1337` — pass `--base-url http://localhost:8001/v1` to hit the actually-running BeigeBox.

## Verifying LLM review findings

LLM code reviews drift on line numbers and produce false positives. **Always verify before acting.** A second-pass with a coding model (`qwen/qwen3-coder-plus` is fast and cheap, 1M context) covers the gap:

1. Build per-finding items (file path + claimed line + finding text + line-numbered file contents).
2. Fan them out with a strict template: `STATUS: confirmed | line-drift | false-positive`.
3. Treat anything other than `confirmed` as needing human re-read. Even `confirmed` may have wrong evidence — qwen mis-verified an f-string SQL pattern in a real session.

The verification round for 20 findings cost ~$0.10 and ran in 33 seconds; the up-front cost of skipping it ("acting on Grok's review verbatim") is hours of chasing false positives or fixing the wrong line.

## Sanity-check checklist

Before declaring "deployed and tested" in the LXC:

- [ ] `systemctl is-active beigebox.service` returns `active`
- [ ] `ss -tlnp | grep 8001` shows BeigeBox listening on `0.0.0.0:8001`
- [ ] `curl http://192.168.1.250:8001/v1/chat/completions` with a real model returns content
- [ ] `journalctl -u beigebox.service --no-pager -n 50` shows no `ERROR` lines from the boot
- [ ] `eth0` has exactly **one** IPv4 address (the static `.250`)

## Anti-patterns

- ❌ `lxc-attach` from a non-root context — silently fails.
- ❌ `nohup ... &` for long tasks inside `lxc-attach` — dies with the attach session.
- ❌ Polling for sentinels by `grep`-ing the typed command — pre-existing pane content matches and fires the watcher early.
- ❌ Editing the source tree's `config.yaml` and assuming the LXC inherits it — it's gitignored. Either edit the LXC copy directly, or rsync it explicitly.
- ❌ Running `python -m beigebox.cli ...` as `ryan` on the host — `beigebox` isn't installed on the host.
- ❌ Pushing to `origin/main` — that's frozen v2. v3 lives on `security/main`.
- ❌ Reading test results from tmux pane scrollback after multiple runs — output from earlier runs mixes in and fakes failures. Always tee pytest output to a file: `pytest ... 2>&1 | tee /opt/beigebox/run.log`, then read `/var/lib/lxc/beigebox/rootfs/opt/beigebox/run.log` from the host root pane.
- ❌ Assuming edited test files take effect immediately — stale `.pyc` bytecode can make pytest run old code. After rsyncing test file changes, run `lxc-attach -n beigebox -- find /opt/beigebox/tests -name "*.pyc" -delete` before re-running.
- ❌ Assuming a sub-agent's commit also synced to the LXC — agents commit to git, not to the LXC filesystem. Always verify with `lxc-attach -n beigebox -- ls /opt/beigebox/tests/<new-file>` and re-rsync if missing.
