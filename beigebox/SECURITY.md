# BeigeBox — Security Posture & Threat Model

This document describes what BeigeBox defends against, what it does not, and
how the trust boundaries inside the system fit together. It is the calibration
document — the design goals are bounded, and so are the guarantees.

If you are looking for vulnerability reporting, jump to **§5**.

---

## 1. Trust boundaries

BeigeBox is a single-tenant control plane in front of LLM providers. The
operator (whoever holds the admin API key) is fully trusted. Everything else
is a boundary worth enforcing.

```
┌──────────────────────┐    Bearer / api-key
│ frontend / API caller│ ────────────────────┐
└──────────────────────┘                     │
                                             ▼
┌──────────────────────────────────────────────────────────────┐
│ BeigeBox                                                     │
│                                                              │
│ ApiKeyMiddleware  → endpoint ACL → model ACL → rate limit    │
│      ▼                                                       │
│ Guardrails (input)  → injection guard → extraction detector  │
│      ▼                                                       │
│ Proxy core          → tool registry  → memory store          │
│      ▼                                                       │
│ Guardrails (output) → secret/PII redaction                   │
└──────────────────────────────────────────────────────────────┘
                                             │
                          ┌──────────────────┴──────────┐
                          ▼                             ▼
                 ┌────────────────┐            ┌────────────────┐
                 │ OpenRouter /   │            │ Local tools    │
                 │ Anthropic /    │            │ (subprocess,   │
                 │ OpenAI         │            │ CDP, MCP)      │
                 └────────────────┘            └────────────────┘
```

**Trusted:** the operator, the host filesystem (within the BeigeBox process
user), the configured upstream API key (`OPENROUTER_API_KEY`).

**Untrusted:** every request body, every prompt, every RAG document, every
tool argument, every response from the upstream model, every header.

---

## 2. What BeigeBox defends against

These are the threats we have specific code paths for. Detection rates cited
in module docstrings are aspirational targets — see `evals/security/` for
the reproducible measurements that ground them.

| Threat | Defense | Module |
|---|---|---|
| Unauthorized API access | Multi-key auth, endpoint ACL, model ACL, rate limit | `auth.py`, `middleware.py` |
| Prompt injection (direct, role manipulation, extraction) | Pattern + semantic + multi-turn analysis | `security/enhanced_injection_guard.py` |
| Model extraction / prompt-inversion probing | Per-session diversity + entropy analysis | `security/extraction_detector.py` |
| RAG poisoning via embedding magnitude attacks | L2-norm z-score against rolling baseline | `security/rag_poisoning_detector.py` |
| RAG content injection | Pattern scan on stored documents | `security/rag_content_scanner.py` |
| Tool-call abuse / argument tampering | Schema + bounds validation | `security/tool_call_validator.py` |
| Conversation tampering after the fact | HMAC-SHA256 per message + hash chain | `security/memory_integrity.py`, `memory_validator.py` |
| API anomaly (rate spikes, unusual endpoints) | Rolling-window heuristics | `security/anomaly_detector.py` |
| Bypass attempts on isolation guards | Honeypot canary tools that alert on touch | `security/honeypots.py` |
| Browser noise leaking through proxy | Path-based silent rejection | `main.py:catch_all` |
| Querystring API-key leakage | `?api_key=` rejected; only headers accepted | `middleware.py` |
| Clickjacking, MIME sniffing, referrer leakage | CSP, X-Frame-Options, nosniff, Referrer-Policy | `middleware.SecurityHeadersMiddleware` |
| Output-side secret/PII leakage | Regex + entropy-based scanner on responses | `security/output_redactor.py` |

## 3. What BeigeBox does **not** defend against

This list matters more than §2. If you need protection against any of these,
add it at a higher layer (network firewall, host hardening, separate process
boundary, code review). BeigeBox will not save you.

1. **Compromise of the upstream LLM provider.** If OpenRouter / Anthropic /
   OpenAI is breached, BeigeBox forwards prompts and bills against the same
   leaked key. We can't detect a server-side compromise upstream.
2. **Model jailbreaks themselves.** Our injection guard reduces the surface
   of *successful* prompt injection that gets through to the model — it does
   not prevent the model from being convinced once a clever prompt arrives.
   Treat model output as untrusted; that's why output-side redaction exists.
3. **Supply-chain compromise of a tool binary.** `security_mcp` wraps third-
   party pen/sec tools (`nmap`, `sqlmap`, `nuclei`, …). If one of those
   binaries is replaced with a trojan, our argv-only `subprocess` policy
   only narrows the call shape — it doesn't audit the binary.
4. **Operator malice.** An admin key holder can delete logs, disable
   guardrails, exfiltrate every conversation. We log admin actions for
   forensics; we don't gate against them.
5. **Side-channel attacks on co-tenants.** BeigeBox is single-tenant by
   design. Running multiple operators against the same instance is not a
   supported deployment.
6. **Local privilege escalation from the BeigeBox process.** We don't run
   under bwrap/firejail by default. A vulnerability in any tool wrapper or
   any router can escalate to the BeigeBox process user. Run it as an
   unprivileged user; consider a sandbox profile if you can't.
7. **Network-level DoS.** Rate limits are per-key, in-process. They do not
   replace a proper edge proxy with connection-level shedding.
8. **Compromise of the host filesystem.** Memory-integrity HMAC keys live
   in `~/.beigebox/memory.key` (mode 0600). If the host is rooted, the key
   is gone. The hash-chain anchor at `~/.beigebox/integrity_anchor.json`
   detects truncation if it's stored on a separate mount/host; if both
   files share the same compromised host, neither survives.
9. **Browser-side session hijacking.** OAuth web-UI sessions use a signed
   cookie. If the browser is compromised, the cookie is too.
10. **Untrusted user code execution.** BeigeBox does not execute user code.
    `security_mcp` invokes specific binaries with argv lists; it does not
    accept arbitrary commands. If a future feature does, sandbox it.
11. **Prompt laundering through BeigeBox.** A caller with a valid API key
    can use the proxy as a path-of-record-cleansing: the request comes from
    BeigeBox's egress IP, the upstream provider's audit trail names
    BeigeBox, and the original caller's identity is only visible in our
    wire log. If our logs are deleted (see #4 and #8), the trail vanishes.
    Operators worried about this should park wire logs on an append-only
    sink (syslog, S3 Object Lock, write-only bucket).

## 3.1 Adversary capabilities — calibrated assumptions

What we assume the attacker *can* and *cannot* do:

| Capability | Assumed |
|---|---|
| Send arbitrary HTTP requests to BeigeBox endpoints | Yes |
| Provide arbitrary prompts / tool args / RAG documents | Yes |
| Forge a valid API key without keychain access | No |
| Read or modify files on the BeigeBox host | No (if so, see §3) |
| Compromise an upstream LLM provider's serving stack | Out of scope |
| Run `nmap` / `sqlmap` / etc. against BeigeBox from outside | No (these are *exposed via* `/pen-mcp`, not against `/pen-mcp`) |
| Social-engineer an operator | Out of scope |
| Replace a system-installed binary on the BeigeBox host | Out of scope (see §3.3) |
| Exploit a CVE in a Python dependency we ship | **In scope** — keep deps current; eval harness should regress on detector failures caused by dep updates |
| Inject content into a RAG document that the operator later ingests | **In scope** — `RAGContentScanner` + per-chunk SHA-256 mitigate |
| Tamper with the audit chain after the fact | **In scope** — hash chain + monotonic seq + separate anchor mitigate (best when anchor is on a different mount) |
| Mount a regex-evasion attack on the output redactor (Unicode confusables, base64-encoded, URL-encoded) | **In scope** — multi-pass redactor includes confusable fold + decode probes |
| Brute-force an API key | Mitigated by per-key rate limit + endpoint ACL; depends on key entropy at issuance |
| Spoof their client IP for the rate cap | Mitigated when X-Forwarded-For is honored *only* from a configured trusted proxy |

---

## 4. Defaults and operator obligations

These choices are deliberate; if any are wrong for your deployment, change
the config rather than the code.

- **Auth defaults to enabled but rejects empty key sets at startup.**
  `auth.enabled: true` + zero resolvable keys raises `AuthMisconfiguredError`.
  To run wide-open intentionally (single-user dev), set `auth.enabled: false`.
- **Guardrails default to off.** Each detector is opt-in. The reasoning: false
  positives in a single-tenant operator's own pipeline are corrosive. Operators
  who serve any third party should turn detectors on per the relevant config
  blocks.
- **HSTS is config-gated and TLS-aware.** Browsers ignore HSTS over plain
  http://; setting it during a TLS test and reverting can lock the operator
  out. The middleware additionally suppresses the header if the active
  request scheme (or `X-Forwarded-Proto`) is not `https`, so a deployment
  half-configured behind plain http won't accidentally pin HSTS. Enable
  `security.hsts.enabled: true` in production *behind* a TLS-terminating
  edge proxy.
- **CDP is opt-in (`tools.cdp.enabled: false`).** *Mimic mode* (which copies
  cookies from the operator's real Chrome profile) is gated separately under
  `tools.cdp.mimic.enabled: true` — review the implications before enabling.
- **Memory-integrity HMAC keys** live in `~/.beigebox/memory.key` (mode 0600)
  or `BEIGEBOX_MEMORY_KEY` env. Set up rotation. The hash chain limits damage
  but does not eliminate it.
- **No PII in logs.** Wire log entries store metadata (token counts, latency,
  endpoint paths). Payloads are referenced by id; full payloads land in the
  blob store gated by audit logging. Redaction runs before write on the
  output side.

---

## 5. Reporting a vulnerability

**Do not** open a public issue.

Email `security@ralabarge.dev` with:
- Title: brief description
- Affected version(s)
- Technical details / proof-of-concept
- Impact: what an attacker can do
- Proposed fix (optional)

**Response timeline:**
- Acknowledgment: 48 hours
- Patch development: 3–7 days, severity-dependent
- Release: as soon as patch is ready
- Public disclosure: 30 days after fix release

**Severity tiers:**
| Level | Description | Target |
|---|---|---|
| Critical | Auth bypass, integrity bypass, RCE | 24h |
| High | Detector regressions, false-negative spike | 2–3d |
| Medium | Information disclosure, perf regression | 5–7d |
| Low | Documentation, minor issues | Next release |

---

## 6. Detector numbers — calibration & honesty

Module docstrings cite TPR/FPR numbers (e.g. injection guard at "87–92% TPR").
**Treat those as design targets, not measured guarantees.** The reproducible
eval harness at `beigebox/evals/security/` is the *only* source of numbers
that should be cited externally, and its corpora are intentionally small
right now (~30–60 rows per suite). The runner prints a "PRELIMINARY" banner
when a suite's corpus is below 200 rows. Do not publish detector TPR/FPR in
release notes or marketing material until the relevant suite passes the
threshold; up to that point the harness exists to catch *regressions*, not
to certify rates.

If you need higher-confidence numbers, expand the corpora — that is the
intended path to silence the banner. Lowering the threshold is not.

## 7. References

- OWASP LLM Top-10 (2025) — extraction (`LLM10`), injection (`LLM01`),
  data poisoning (`LLM03`), insecure output handling (`LLM02`).
- `BEIGEBOX_IS_NOT.md` — the project's NO list, the negative space of this
  document.
- `evals/security/` — reproducible TPR/FPR runs that calibrate detector
  claims.
- `beigebox/security/policy.py` — WAF-style per-route DSL.
- `beigebox/security/output_redactor.py` — multi-pass output redaction.
- `beigebox/security/memory_integrity.py` — HMAC daily subkey + hash-chained
  audit log + anchor.
