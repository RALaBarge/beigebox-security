"""
Bash escape-hatch tool for the operator.

This is the fallback for operations that don't have a dedicated skill yet.
Prefer named skills (lsof, grep-codebase, deploy, etc.) over this tool —
wiretap reads are more useful when they say "lsof" than "bash: lsof -i :8080".

Execution model
---------------
1. SafePath validates the working_dir so the process starts in-scope.
2. If bwrap is available, the command runs inside the named sandbox profile.
3. Env sanitization strips credentials before the subprocess inherits env.
4. Output is capped at 100 KB; timeout defaults to 120 s.

Input JSON
----------
{
  "command": "lsof -i :8080",
  "profile": "code-task",   // optional, default from config
  "timeout": 30             // optional, seconds
}
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path

from beigebox.security.safe_path import UnsafePathError
from beigebox.tools.sandbox import PROFILES, build_argv, _DEFAULT_PROFILE
from beigebox.tools._ctx import get_working_dir as _get_working_dir

logger = logging.getLogger(__name__)

_MAX_OUTPUT_BYTES = 100 * 1024
_DEFAULT_TIMEOUT = 120

_STRIP_ENV = {
    "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY", "DATABASE_URL", "SECRET_KEY", "DJANGO_SECRET_KEY",
    "ENCRYPTION_KEY", "PRIVATE_KEY", "STRIPE_SECRET_KEY", "SENDGRID_API_KEY",
    "TWILIO_AUTH_TOKEN", "SLACK_TOKEN", "SLACK_BOT_TOKEN",
    "NPM_TOKEN", "PYPI_TOKEN",
}


def _sanitized_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in _STRIP_ENV:
        env.pop(key, None)
    return env


def _get_default_profile() -> str:
    try:
        from beigebox.config import get_config
        return get_config().get("tools", {}).get("bash", {}).get("default_profile", _DEFAULT_PROFILE)
    except Exception:
        return _DEFAULT_PROFILE


def _get_ssh_dir() -> str | None:
    try:
        from beigebox.config import get_config
        return get_config().get("tools", {}).get("bash", {}).get("ssh_dir") or None
    except Exception:
        return None


class BashTool:
    description = (
        "Execute a shell command. Use only when no dedicated skill covers the task. "
        'Input JSON: {"command": "lsof -i :8080"} '
        f'Optional: "profile" ({", ".join(PROFILES)}), "timeout" (seconds). '
        "code-task=no network; deploy-task=network+ssh; audit-task=network+read-only; open=network+rw."
    )

    def run(self, input_text: str) -> str:
        try:
            params = json.loads(input_text)
        except json.JSONDecodeError:
            params = {"command": input_text.strip()}

        command = params.get("command", "")
        if not isinstance(command, str) or not command.strip():
            return "Error: command required"

        profile = params.get("profile", _get_default_profile())
        if profile not in PROFILES:
            logger.warning("Unknown profile %r — using %s", profile, _DEFAULT_PROFILE)
            profile = _DEFAULT_PROFILE

        timeout = int(params.get("timeout", _DEFAULT_TIMEOUT))
        wd_override = params.get("working_dir", "")
        wd = Path(wd_override).resolve() if wd_override else _get_working_dir()

        try:
            sandbox = build_argv(profile, working_dir=wd, ssh_dir=_get_ssh_dir())
        except UnsafePathError as exc:
            return f"Error: {exc}"

        if sandbox:
            argv = sandbox + ["/bin/bash", "-c", command]
        else:
            argv = ["bash", "-c", command]

        logger.info("bash [%s]: %s", profile, command[:120])

        try:
            result = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=_sanitized_env(),
                cwd=None if sandbox else str(wd),
            )
        except subprocess.TimeoutExpired:
            return f"Error: timed out after {timeout}s"
        except PermissionError as exc:
            return f"Error: permission denied: {exc}"
        except OSError as exc:
            return f"Error: {exc}"

        output = result.stdout
        if result.stderr:
            output = (output + result.stderr) if output else result.stderr

        if len(output.encode("utf-8", errors="replace")) > _MAX_OUTPUT_BYTES:
            truncated = output.encode("utf-8", errors="replace")[:_MAX_OUTPUT_BYTES]
            output = truncated.decode("utf-8", errors="replace") + "\n... [truncated at 100KB]"

        if result.returncode != 0 and not output:
            output = f"[exit {result.returncode}]"

        return output
