"""
Parameter validation integration layer.

Wraps the multi-tier MCP parameter validator, provides tool rule metadata,
and maps results to the microservice response format.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ValidationIssue:
    """Single validation issue found during parameter checking."""
    tier: str          # "schema", "constraint", "semantic", "isolation"
    severity: str      # "critical", "high", "medium", "low"
    tool: str
    field: str
    message: str
    attack_type: str
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "tier": self.tier,
            "severity": self.severity,
            "tool": self.tool,
            "field": self.field,
            "message": self.message,
            "attack_type": self.attack_type,
            "remediation": self.remediation,
        }


@dataclass
class MCPValidationResult:
    """Structured validation result for a single tool call."""
    valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    sanitized_params: dict = field(default_factory=dict)
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "issues": [i.to_dict() for i in self.issues],
            "sanitized_params": self.sanitized_params,
            "elapsed_ms": round(self.elapsed_ms, 2),
        }


# ---------------------------------------------------------------------------
# Compiled patterns (module-level for performance)
# ---------------------------------------------------------------------------

_PATH_TRAVERSAL = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c)",
    re.IGNORECASE,
)
_UNC_PATH = re.compile(r"^\\\\[^\\]+\\[^\\]+")
_NULL_BYTE = re.compile(r"\x00")

_DANGEROUS_IMPORTS = re.compile(
    r"\b(?:import|from)\s+(?:os|sys|subprocess|socket|shutil|signal|ctypes"
    r"|multiprocessing|threading|requests|urllib|http\.client|ftplib"
    r"|smtplib|telnetlib|pickle|shelve|marshal|tempfile|glob"
    r"|pathlib|importlib|builtins|code|codeop|compileall"
    r"|py_compile|zipimport)\b",
)
_DANGEROUS_BUILTINS = re.compile(
    r"\b(?:eval|exec|compile|__import__|globals|locals|getattr|setattr"
    r"|delattr|breakpoint|open)\s*\(",
)
_DUNDER_ACCESS = re.compile(
    r"__(?:subclasses|bases|mro|class|globals|builtins|import|code|func)__",
)
_OS_ENVIRON = re.compile(r"\bos\.environ\b")
_SUBPROCESS_CALL = re.compile(
    r"\bsubprocess\.(?:call|run|Popen|check_output|check_call|getoutput|getstatusoutput)\b",
)

_NESTED_QUANTIFIER = re.compile(
    r"\([^)]*[+*][^)]*\)[+*?]|\([^)]*\{[^}]+\}[^)]*\)[+*?{]",
)
_REPEATED_ALTERNATION = re.compile(
    r"\((?:[^)]*\|){5,}[^)]*\)[+*]",
)

_LOCALHOST_PATTERNS = re.compile(
    r"^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|0x7f|2130706433)$",
    re.IGNORECASE,
)

_ALLOWED_SCHEMES = {"http", "https"}
_DANGEROUS_SCHEMES = {
    "javascript", "data", "file", "ftp", "gopher", "ldap",
    "dict", "sftp", "ssh", "telnet", "tftp", "vnc",
}

_RFC1918_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
_LINK_LOCAL = ipaddress.ip_network("169.254.0.0/16")
_LOOPBACK_V4 = ipaddress.ip_network("127.0.0.0/8")
_LOOPBACK_V6 = ipaddress.ip_network("::1/128")


# ---------------------------------------------------------------------------
# Tool rules metadata (for GET /rules/{tool_name})
# ---------------------------------------------------------------------------

TOOL_RULES: dict[str, dict] = {
    "workspace_file": {
        "tool": "workspace_file",
        "description": "File I/O within workspace sandbox",
        "tiers": ["schema", "constraint", "semantic", "isolation"],
        "parameters": {
            "action": {"type": "string", "allowed": ["read", "write", "append", "list"], "required": True},
            "path": {"type": "string", "required": True, "constraints": ["no path traversal", "must resolve within workspace"]},
            "content": {"type": "string", "required": False, "constraints": ["max 64 KB"]},
        },
        "attack_vectors": ["path_traversal", "null_byte_injection", "symlink_escape"],
    },
    "network_audit": {
        "tool": "network_audit",
        "description": "Network scanning and discovery",
        "tiers": ["schema", "constraint", "semantic"],
        "parameters": {
            "network": {"type": "string", "required": False, "constraints": ["RFC1918 only", "min CIDR /24"]},
            "ip": {"type": "string", "required": False, "constraints": ["private IP only", "no loopback"]},
            "ports": {"type": "string", "required": False, "constraints": ["max 100 ports"]},
            "timeout": {"type": "float", "required": False, "constraints": ["max 30s", "must be positive"]},
        },
        "attack_vectors": ["ssrf", "resource_exhaustion"],
    },
    "cdp": {
        "tool": "cdp",
        "description": "Chrome DevTools Protocol browser control",
        "tiers": ["schema", "constraint", "semantic"],
        "parameters": {
            "url": {"type": "string", "required": False, "constraints": ["http/https only", "no internal IPs"]},
            "selector": {"type": "string", "required": False, "constraints": ["no shell metacharacters"]},
        },
        "attack_vectors": ["ssrf", "code_injection", "dangerous_schemes"],
    },
    "python_interpreter": {
        "tool": "python_interpreter",
        "description": "Sandboxed Python code execution",
        "tiers": ["schema", "constraint", "semantic"],
        "parameters": {
            "code": {"type": "string", "required": True, "constraints": ["max 10000 chars", "no dangerous imports", "no dangerous builtins", "no dunder access"]},
        },
        "attack_vectors": ["code_injection", "sandbox_escape", "credential_theft"],
    },
    "apex_analyzer": {
        "tool": "apex_analyzer",
        "description": "Salesforce Apex/SOQL analysis",
        "tiers": ["schema", "constraint", "semantic"],
        "parameters": {
            "query": {"type": "string", "required": False, "constraints": ["max 4000 chars"]},
            "soql_query": {"type": "string", "required": False, "constraints": ["no SQL injection patterns"]},
        },
        "attack_vectors": ["redos", "sql_injection", "resource_exhaustion"],
    },
    "confluence_crawler": {
        "tool": "confluence_crawler",
        "description": "Confluence wiki content retrieval",
        "tiers": ["schema", "constraint", "semantic"],
        "parameters": {
            "url": {"type": "string", "required": False, "constraints": ["http/https only", "no internal IPs"]},
        },
        "attack_vectors": ["ssrf", "dangerous_schemes"],
    },
    "web_scraper": {
        "tool": "web_scraper",
        "description": "Web page content extraction",
        "tiers": ["schema", "constraint", "semantic"],
        "parameters": {
            "url": {"type": "string", "required": True, "constraints": ["http/https only", "no internal IPs", "max 2048 chars"]},
        },
        "attack_vectors": ["ssrf", "dangerous_schemes", "resource_exhaustion"],
    },
    "browserbox": {
        "tool": "browserbox",
        "description": "Browser automation wrapper",
        "tiers": ["schema", "semantic"],
        "parameters": {
            "tool": {"type": "string", "required": False},
            "input": {"type": "string", "required": False, "constraints": ["URL validation on navigate/open actions"]},
        },
        "attack_vectors": ["ssrf", "code_injection"],
    },
    "bluetruth": {
        "tool": "bluetruth",
        "description": "Bluetooth diagnostics and discovery",
        "tiers": ["schema", "semantic"],
        "parameters": {
            "command": {"type": "string", "required": False},
        },
        "attack_vectors": ["code_injection", "shell_injection"],
    },
}


# ---------------------------------------------------------------------------
# Remediation hints per attack type
# ---------------------------------------------------------------------------

_REMEDIATION: dict[str, str] = {
    "path_traversal": "Use relative paths within workspace (e.g., 'out/report.md'). Remove any '../' sequences.",
    "null_byte_injection": "Remove null bytes from the path string.",
    "malformed_input": "Ensure parameters are valid JSON with correct types.",
    "invalid_action": "Use one of the allowed actions: read, write, append, list.",
    "missing_field": "Provide the required field for this action.",
    "resource_exhaustion": "Reduce the size/scope of the request within documented limits.",
    "ssrf": "Use public URLs only. Internal/private IP addresses are blocked.",
    "code_injection": "Remove dangerous imports, builtins, or shell metacharacters.",
    "redos": "Simplify the regex pattern. Avoid nested quantifiers like (a+)+.",
    "sql_injection": "Use parameterized queries. Avoid quote-based injection patterns.",
    "sandbox_escape": "Remove dunder attribute access (__subclasses__, __bases__, etc.).",
}


# ---------------------------------------------------------------------------
# ParameterValidator
# ---------------------------------------------------------------------------

class ParameterValidator:
    """
    Multi-tier MCP parameter validator.

    Supports 9 tools: workspace_file, network_audit, cdp, python_interpreter,
    apex_analyzer, confluence_crawler, web_scraper, browserbox, bluetruth.
    """

    def __init__(
        self,
        workspace_root: str | Path = "./workspace",
        allow_localhost_cdp: bool = False,
        max_code_length: int = 10_000,
        max_query_length: int = 4_000,
        max_network_cidr: int = 24,
        max_ports: int = 100,
        max_network_timeout: float = 30.0,
    ):
        self.workspace_root = Path(workspace_root).resolve()
        self.allow_localhost_cdp = allow_localhost_cdp
        self.max_code_length = max_code_length
        self.max_query_length = max_query_length
        self.max_network_cidr = max_network_cidr
        self.max_ports = max_ports
        self.max_network_timeout = max_network_timeout

        self._validators = {
            "workspace_file": self._validate_workspace_file,
            "network_audit": self._validate_network_audit,
            "cdp": self._validate_cdp,
            "python": self._validate_python,
            "python_interpreter": self._validate_python,
            "apex_analyzer": self._validate_apex_analyzer,
            "confluence_crawler": self._validate_confluence_crawler,
            "web_scraper": self._validate_web_scraper,
            "browserbox": self._validate_browserbox,
            "bluetruth": self._validate_bluetruth,
        }

        self._safe_python_modules = {
            "math", "json", "re", "datetime", "collections", "itertools",
            "functools", "operator", "string", "textwrap", "unicodedata",
            "decimal", "fractions", "random", "statistics", "hashlib",
            "hmac", "base64", "binascii", "struct", "copy", "pprint",
            "enum", "dataclasses", "typing", "abc", "numbers",
            "csv", "io",
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, tool_name: str, params: Any, allow_unsafe: bool = False) -> MCPValidationResult:
        """Validate parameters for a tool call."""
        start = time.monotonic()
        base_tool = tool_name.split(".")[0]
        parsed = self._parse_params(params)

        validator_fn = self._validators.get(base_tool)
        if validator_fn is None:
            elapsed = (time.monotonic() - start) * 1000
            return MCPValidationResult(
                valid=True,
                issues=[],
                sanitized_params=parsed if isinstance(parsed, dict) else {"_raw": params},
                elapsed_ms=elapsed,
            )

        result = validator_fn(base_tool, parsed, params)

        # If allow_unsafe, downgrade non-critical issues to warnings (still valid)
        if allow_unsafe and not result.valid:
            has_critical = any(i.severity == "critical" for i in result.issues)
            if not has_critical:
                result.valid = True

        # Attach remediation hints
        for issue in result.issues:
            issue.remediation = _REMEDIATION.get(issue.attack_type, "Review the parameter value.")

        result.elapsed_ms = (time.monotonic() - start) * 1000
        return result

    def validate_batch(self, calls: list[dict]) -> list[MCPValidationResult]:
        """Validate a batch of tool calls."""
        return [
            self.validate(
                call.get("tool_name", call.get("tool", "")),
                call.get("parameters", call.get("params", call.get("input", {}))),
                call.get("allow_unsafe", False),
            )
            for call in calls
        ]

    def get_rules(self, tool_name: str) -> Optional[dict]:
        """Return validation rules for a tool, or None if unknown."""
        base = tool_name.split(".")[0]
        # Map python alias
        if base == "python":
            base = "python_interpreter"
        return TOOL_RULES.get(base)

    @property
    def supported_tools(self) -> list[str]:
        """Return sorted list of tools with validation rules."""
        return sorted(TOOL_RULES.keys())

    # ------------------------------------------------------------------
    # Parameter parsing
    # ------------------------------------------------------------------

    def _parse_params(self, params: Any) -> Any:
        if isinstance(params, str):
            try:
                return json.loads(params)
            except (json.JSONDecodeError, TypeError):
                return params
        return params

    # ------------------------------------------------------------------
    # Tool: WorkspaceFile
    # ------------------------------------------------------------------

    def _validate_workspace_file(self, tool: str, parsed: Any, raw: Any) -> MCPValidationResult:
        issues: list[ValidationIssue] = []
        sanitized = dict(parsed) if isinstance(parsed, dict) else {}

        if not isinstance(parsed, dict):
            issues.append(ValidationIssue(
                tier="schema", severity="critical", tool=tool, field="_root",
                message="Parameters must be a JSON object",
                attack_type="malformed_input",
            ))
            return MCPValidationResult(valid=False, issues=issues, sanitized_params={})

        action = parsed.get("action", "")
        path = str(parsed.get("path", ""))
        content = parsed.get("content", "")
        allowed_actions = {"read", "write", "append", "list"}

        if action and action.lower() not in allowed_actions:
            issues.append(ValidationIssue(
                tier="schema", severity="high", tool=tool, field="action",
                message=f"Invalid action '{action}', must be one of {allowed_actions}",
                attack_type="invalid_action",
            ))

        if action in {"read", "write", "append"} and not path:
            issues.append(ValidationIssue(
                tier="schema", severity="high", tool=tool, field="path",
                message=f"path required for action='{action}'",
                attack_type="missing_field",
            ))

        if isinstance(content, str) and len(content.encode("utf-8", errors="replace")) > 65_536:
            issues.append(ValidationIssue(
                tier="constraint", severity="medium", tool=tool, field="content",
                message="Content exceeds 64 KB limit",
                attack_type="resource_exhaustion",
            ))

        if path:
            if _NULL_BYTE.search(path):
                issues.append(ValidationIssue(
                    tier="semantic", severity="critical", tool=tool, field="path",
                    message="Null byte detected in path",
                    attack_type="path_traversal",
                ))
            if _PATH_TRAVERSAL.search(path):
                issues.append(ValidationIssue(
                    tier="semantic", severity="critical", tool=tool, field="path",
                    message=f"Path traversal pattern detected: '{path}'",
                    attack_type="path_traversal",
                ))
            if _UNC_PATH.search(path):
                issues.append(ValidationIssue(
                    tier="semantic", severity="critical", tool=tool, field="path",
                    message="UNC path detected",
                    attack_type="path_traversal",
                ))
            if path.startswith("/") and not path.startswith(("/workspace/", str(self.workspace_root))):
                issues.append(ValidationIssue(
                    tier="semantic", severity="critical", tool=tool, field="path",
                    message=f"Absolute path outside workspace: '{path}'",
                    attack_type="path_traversal",
                ))

        if path and not issues:
            sanitized_path = self._canonicalize_workspace_path(path)
            if sanitized_path is None:
                issues.append(ValidationIssue(
                    tier="isolation", severity="high", tool=tool, field="path",
                    message="Path resolves outside workspace after canonicalization",
                    attack_type="path_traversal",
                ))
            else:
                sanitized["path"] = sanitized_path

        return MCPValidationResult(valid=len(issues) == 0, issues=issues, sanitized_params=sanitized)

    def _canonicalize_workspace_path(self, path: str) -> Optional[str]:
        clean = path
        for prefix in ("workspace/out/", "workspace/in/", "workspace/", "/workspace/out/", "/workspace/in/", "/workspace/"):
            if clean.startswith(prefix):
                clean = clean[len(prefix):]
                break
        candidate = (self.workspace_root / "out" / clean).resolve()
        try:
            candidate.relative_to(self.workspace_root)
            return str(candidate.relative_to(self.workspace_root))
        except ValueError:
            return None

    # ------------------------------------------------------------------
    # Tool: NetworkAudit
    # ------------------------------------------------------------------

    def _validate_network_audit(self, tool: str, parsed: Any, raw: Any) -> MCPValidationResult:
        issues: list[ValidationIssue] = []
        sanitized = dict(parsed) if isinstance(parsed, dict) else {}

        if not isinstance(parsed, dict):
            if isinstance(parsed, str):
                sanitized = {"command": parsed}
            else:
                issues.append(ValidationIssue(
                    tier="schema", severity="high", tool=tool, field="_root",
                    message="Parameters must be a JSON object or command string",
                    attack_type="malformed_input",
                ))
                return MCPValidationResult(valid=False, issues=issues, sanitized_params={})

        network = parsed.get("network", parsed.get("subnet", "")) if isinstance(parsed, dict) else ""
        ip = parsed.get("ip", "") if isinstance(parsed, dict) else ""
        ports = parsed.get("ports", "") if isinstance(parsed, dict) else ""
        timeout = parsed.get("timeout_seconds", parsed.get("timeout", None)) if isinstance(parsed, dict) else None

        if network:
            try:
                net = ipaddress.ip_network(network, strict=False)
                if net.prefixlen < self.max_network_cidr:
                    issues.append(ValidationIssue(
                        tier="constraint", severity="high", tool=tool, field="network",
                        message=f"CIDR /{net.prefixlen} too broad, minimum /{self.max_network_cidr}",
                        attack_type="resource_exhaustion",
                    ))
                if not any(net.subnet_of(rfc) for rfc in _RFC1918_RANGES):
                    issues.append(ValidationIssue(
                        tier="constraint", severity="critical", tool=tool, field="network",
                        message=f"Network '{network}' is not RFC1918 private",
                        attack_type="ssrf",
                    ))
            except ValueError:
                issues.append(ValidationIssue(
                    tier="schema", severity="high", tool=tool, field="network",
                    message=f"Invalid network: '{network}'",
                    attack_type="malformed_input",
                ))

        if ip:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_loopback:
                    issues.append(ValidationIssue(
                        tier="constraint", severity="high", tool=tool, field="ip",
                        message=f"Loopback address '{ip}' not allowed",
                        attack_type="ssrf",
                    ))
                if not ip_obj.is_private:
                    issues.append(ValidationIssue(
                        tier="constraint", severity="critical", tool=tool, field="ip",
                        message=f"IP '{ip}' is not RFC1918 private",
                        attack_type="ssrf",
                    ))
                if ip_obj in _LINK_LOCAL:
                    issues.append(ValidationIssue(
                        tier="constraint", severity="medium", tool=tool, field="ip",
                        message=f"Link-local address '{ip}' not allowed",
                        attack_type="ssrf",
                    ))
            except ValueError:
                issues.append(ValidationIssue(
                    tier="schema", severity="high", tool=tool, field="ip",
                    message=f"Invalid IP address: '{ip}'",
                    attack_type="malformed_input",
                ))

        if ports and isinstance(ports, str) and ports not in {"top1000", "top-1000", "top-100", "top100", "common"}:
            try:
                port_list = self._parse_port_spec(ports)
                if len(port_list) > self.max_ports:
                    issues.append(ValidationIssue(
                        tier="constraint", severity="medium", tool=tool, field="ports",
                        message=f"Port count {len(port_list)} exceeds max {self.max_ports}",
                        attack_type="resource_exhaustion",
                    ))
            except ValueError:
                issues.append(ValidationIssue(
                    tier="schema", severity="medium", tool=tool, field="ports",
                    message=f"Invalid port specification: '{ports}'",
                    attack_type="malformed_input",
                ))

        if timeout is not None:
            try:
                t = float(timeout)
                if t > self.max_network_timeout:
                    issues.append(ValidationIssue(
                        tier="constraint", severity="medium", tool=tool, field="timeout",
                        message=f"Timeout {t}s exceeds max {self.max_network_timeout}s",
                        attack_type="resource_exhaustion",
                    ))
                    sanitized["timeout_seconds"] = self.max_network_timeout
                elif t <= 0:
                    issues.append(ValidationIssue(
                        tier="schema", severity="medium", tool=tool, field="timeout",
                        message="Timeout must be positive",
                        attack_type="malformed_input",
                    ))
            except (ValueError, TypeError):
                issues.append(ValidationIssue(
                    tier="schema", severity="medium", tool=tool, field="timeout",
                    message=f"Timeout must be numeric, got '{timeout}'",
                    attack_type="malformed_input",
                ))

        return MCPValidationResult(valid=len(issues) == 0, issues=issues, sanitized_params=sanitized)

    def _parse_port_spec(self, spec: str) -> list[int]:
        ports = []
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                lo_int, hi_int = int(lo), int(hi)
                if lo_int < 1 or hi_int > 65535 or lo_int > hi_int:
                    raise ValueError(f"Invalid port range: {part}")
                ports.extend(range(lo_int, hi_int + 1))
            else:
                p = int(part)
                if p < 1 or p > 65535:
                    raise ValueError(f"Invalid port: {p}")
                ports.append(p)
        return ports

    # ------------------------------------------------------------------
    # Tool: CDP
    # ------------------------------------------------------------------

    def _validate_cdp(self, tool: str, parsed: Any, raw: Any) -> MCPValidationResult:
        issues: list[ValidationIssue] = []
        sanitized = dict(parsed) if isinstance(parsed, dict) else {}

        url = ""
        if isinstance(parsed, str):
            url = parsed.strip()
            sanitized = {"url": url}
        elif isinstance(parsed, dict):
            url = parsed.get("url", "")
            selector = parsed.get("selector", "")
            if selector and re.search(r"[`$;|<>]", selector):
                issues.append(ValidationIssue(
                    tier="semantic", severity="medium", tool=tool, field="selector",
                    message="Suspicious characters in CSS selector",
                    attack_type="code_injection",
                ))

        if url:
            issues.extend(self._validate_url(tool, url))

        return MCPValidationResult(valid=len(issues) == 0, issues=issues, sanitized_params=sanitized)

    def _validate_url(self, tool: str, url: str) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        try:
            parsed = urlparse(url)
        except Exception:
            issues.append(ValidationIssue(
                tier="schema", severity="high", tool=tool, field="url",
                message=f"Malformed URL: '{url[:100]}'",
                attack_type="malformed_input",
            ))
            return issues

        scheme = (parsed.scheme or "").lower()
        if scheme in _DANGEROUS_SCHEMES:
            issues.append(ValidationIssue(
                tier="semantic", severity="critical", tool=tool, field="url",
                message=f"Dangerous URL scheme '{scheme}:' blocked",
                attack_type="code_injection" if scheme == "javascript" else "ssrf",
            ))
            return issues

        if scheme and scheme not in _ALLOWED_SCHEMES:
            issues.append(ValidationIssue(
                tier="constraint", severity="high", tool=tool, field="url",
                message=f"URL scheme '{scheme}' not in whitelist {_ALLOWED_SCHEMES}",
                attack_type="ssrf",
            ))

        if len(url) > 2048:
            issues.append(ValidationIssue(
                tier="constraint", severity="medium", tool=tool, field="url",
                message="URL exceeds 2048 character limit",
                attack_type="resource_exhaustion",
            ))

        hostname = (parsed.hostname or "").lower()
        if hostname and not self.allow_localhost_cdp:
            if _LOCALHOST_PATTERNS.match(hostname):
                issues.append(ValidationIssue(
                    tier="semantic", severity="high", tool=tool, field="url",
                    message=f"SSRF: localhost/loopback address '{hostname}' blocked",
                    attack_type="ssrf",
                ))
            else:
                try:
                    ip_obj = ipaddress.ip_address(hostname)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                        issues.append(ValidationIssue(
                            tier="semantic", severity="high", tool=tool, field="url",
                            message=f"SSRF: private/internal IP '{hostname}' blocked",
                            attack_type="ssrf",
                        ))
                except ValueError:
                    pass

        return issues

    # ------------------------------------------------------------------
    # Tool: PythonInterpreter
    # ------------------------------------------------------------------

    def _validate_python(self, tool: str, parsed: Any, raw: Any) -> MCPValidationResult:
        issues: list[ValidationIssue] = []
        code = parsed if isinstance(parsed, str) else str(raw) if raw else ""
        sanitized = {"code": code}

        if len(code) > self.max_code_length:
            issues.append(ValidationIssue(
                tier="constraint", severity="medium", tool=tool, field="code",
                message=f"Code exceeds {self.max_code_length} character limit ({len(code)} chars)",
                attack_type="resource_exhaustion",
            ))

        if not code.strip():
            issues.append(ValidationIssue(
                tier="schema", severity="low", tool=tool, field="code",
                message="Empty code string",
                attack_type="malformed_input",
            ))
            return MCPValidationResult(valid=False, issues=issues, sanitized_params=sanitized)

        for match in _DANGEROUS_IMPORTS.finditer(code):
            import_text = match.group(0)
            m = re.search(r"(?:import|from)\s+(\w+)", import_text)
            if m and m.group(1) not in self._safe_python_modules:
                issues.append(ValidationIssue(
                    tier="semantic", severity="critical", tool=tool, field="code",
                    message=f"Dangerous import blocked: '{import_text.strip()}'",
                    attack_type="code_injection",
                ))

        for match in _DANGEROUS_BUILTINS.finditer(code):
            builtin_name = match.group(0).split("(")[0].strip()
            if builtin_name == "open":
                context_start = max(0, match.start() - 5)
                context_end = min(len(code), match.end() + 100)
                context = code[context_start:context_end]
                if "workspace/" in context or "workspace\\" in context:
                    continue
                issues.append(ValidationIssue(
                    tier="semantic", severity="high", tool=tool, field="code",
                    message="File open() outside workspace context blocked",
                    attack_type="code_injection",
                ))
            else:
                issues.append(ValidationIssue(
                    tier="semantic", severity="critical", tool=tool, field="code",
                    message=f"Dangerous builtin '{builtin_name}' blocked",
                    attack_type="code_injection",
                ))

        for match in _DUNDER_ACCESS.finditer(code):
            issues.append(ValidationIssue(
                tier="semantic", severity="critical", tool=tool, field="code",
                message=f"Dunder attribute access blocked: '{match.group(0)}'",
                attack_type="code_injection",
            ))

        if _OS_ENVIRON.search(code):
            issues.append(ValidationIssue(
                tier="semantic", severity="critical", tool=tool, field="code",
                message="os.environ access blocked (credential theft vector)",
                attack_type="code_injection",
            ))

        if _SUBPROCESS_CALL.search(code):
            issues.append(ValidationIssue(
                tier="semantic", severity="critical", tool=tool, field="code",
                message="subprocess call blocked",
                attack_type="code_injection",
            ))

        return MCPValidationResult(valid=len(issues) == 0, issues=issues, sanitized_params=sanitized)

    # ------------------------------------------------------------------
    # Tool: ApexAnalyzer
    # ------------------------------------------------------------------

    def _validate_apex_analyzer(self, tool: str, parsed: Any, raw: Any) -> MCPValidationResult:
        issues: list[ValidationIssue] = []
        if isinstance(parsed, dict):
            query = parsed.get("soql_query", parsed.get("query", parsed.get("input", "")))
            sanitized = dict(parsed)
        else:
            query = str(parsed) if parsed else str(raw) if raw else ""
            sanitized = {"query": query}

        if len(query) > self.max_query_length:
            issues.append(ValidationIssue(
                tier="constraint", severity="medium", tool=tool, field="query",
                message=f"Query exceeds {self.max_query_length} char limit ({len(query)} chars)",
                attack_type="resource_exhaustion",
            ))

        if _NESTED_QUANTIFIER.search(query):
            issues.append(ValidationIssue(
                tier="semantic", severity="critical", tool=tool, field="query",
                message="ReDoS pattern detected: nested quantifiers",
                attack_type="redos",
            ))

        if _REPEATED_ALTERNATION.search(query):
            issues.append(ValidationIssue(
                tier="semantic", severity="high", tool=tool, field="query",
                message="ReDoS pattern detected: repeated alternation",
                attack_type="redos",
            ))

        if query.count("'") >= 4:
            if re.search(r"'\s*(OR|AND)\s*'[^']*'\s*=\s*'", query, re.IGNORECASE):
                issues.append(ValidationIssue(
                    tier="semantic", severity="high", tool=tool, field="query",
                    message="SQL injection pattern detected in SOQL query",
                    attack_type="sql_injection",
                ))

        return MCPValidationResult(valid=len(issues) == 0, issues=issues, sanitized_params=sanitized)

    # ------------------------------------------------------------------
    # Tool: ConfluenceCrawler
    # ------------------------------------------------------------------

    def _validate_confluence_crawler(self, tool: str, parsed: Any, raw: Any) -> MCPValidationResult:
        issues: list[ValidationIssue] = []
        if isinstance(parsed, dict):
            url = parsed.get("url", parsed.get("start_url", ""))
            sanitized = dict(parsed)
        elif isinstance(parsed, str):
            url = parsed
            sanitized = {"url": url}
        else:
            sanitized = {}
            url = ""

        if url:
            issues.extend(self._validate_url(tool, url))

        return MCPValidationResult(valid=len(issues) == 0, issues=issues, sanitized_params=sanitized)

    # ------------------------------------------------------------------
    # Tool: WebScraper
    # ------------------------------------------------------------------

    def _validate_web_scraper(self, tool: str, parsed: Any, raw: Any) -> MCPValidationResult:
        issues: list[ValidationIssue] = []
        if isinstance(parsed, dict):
            url = parsed.get("url", "")
            sanitized = dict(parsed)
        elif isinstance(parsed, str):
            url = parsed
            sanitized = {"url": url}
        else:
            sanitized = {}
            url = ""

        if url:
            issues.extend(self._validate_url(tool, url))

        return MCPValidationResult(valid=len(issues) == 0, issues=issues, sanitized_params=sanitized)

    # ------------------------------------------------------------------
    # Tool: Browserbox
    # ------------------------------------------------------------------

    def _validate_browserbox(self, tool: str, parsed: Any, raw: Any) -> MCPValidationResult:
        issues: list[ValidationIssue] = []
        sanitized = dict(parsed) if isinstance(parsed, dict) else {"_raw": raw}

        if isinstance(parsed, dict):
            inner_input = parsed.get("input", "")
            inner_tool = parsed.get("tool", "")
            if "navigate" in str(inner_tool).lower() or "open" in str(inner_tool).lower():
                if isinstance(inner_input, str) and inner_input.strip():
                    issues.extend(self._validate_url(tool, inner_input.strip()))

        return MCPValidationResult(valid=len(issues) == 0, issues=issues, sanitized_params=sanitized)

    # ------------------------------------------------------------------
    # Tool: BlueTruth
    # ------------------------------------------------------------------

    def _validate_bluetruth(self, tool: str, parsed: Any, raw: Any) -> MCPValidationResult:
        issues: list[ValidationIssue] = []
        sanitized = dict(parsed) if isinstance(parsed, dict) else {"_raw": raw}

        check_str = json.dumps(parsed) if isinstance(parsed, dict) else str(parsed)
        shell_injection = re.compile(r"[`$;|<>&]|\$\(|&&|\|\|")
        if shell_injection.search(check_str):
            issues.append(ValidationIssue(
                tier="semantic", severity="high", tool=tool, field="_input",
                message="Shell metacharacters detected in input",
                attack_type="code_injection",
            ))

        return MCPValidationResult(valid=len(issues) == 0, issues=issues, sanitized_params=sanitized)
