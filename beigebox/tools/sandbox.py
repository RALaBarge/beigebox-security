"""
Sandbox profiles for operator tool execution.

Named profiles select a bwrap argument set. Each profile balances capability
against isolation — choose the least-privileged profile that allows the task.

Profiles
--------
code-task   No network. Project dir rw, rest of fs invisible. Default for
            read/write/edit/bash when no profile specified.
deploy-task Network on. Project dir rw. SSH dir bind-mounted read-only when
            an ssh_dir is configured. Use for git push, rsync, deploy scripts.
audit-task  Network on. Project dir read-only. Use for scanning, recon,
            read-only analysis that needs outbound access.
open        Network on. Project dir rw. No extra restrictions beyond
            filesystem scoping. Escape hatch when other profiles are too tight.

All profiles
  - --die-with-parent  (sandbox cleans up if BeigeBox dies)
  - no /home, no /root, no /etc (writable)
  - /tmp as tmpfs scratch

If bwrap is not available the profile is silently skipped and the command
runs under the caller's process constraints (SafePath still applies).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

PROFILES = ("code-task", "deploy-task", "audit-task", "open")
_DEFAULT_PROFILE = "code-task"


@lru_cache(maxsize=1)
def bwrap_available() -> bool:
    """Probe bwrap once per process. Cached — availability doesn't change."""
    bwrap = shutil.which("bwrap")
    if not bwrap:
        logger.info("bwrap not found — sandbox profiles inactive")
        return False
    try:
        subprocess.run(
            [
                bwrap,
                "--die-with-parent",
                "--unshare-all",
                "--ro-bind", "/usr", "/usr",
                "--ro-bind-try", "/bin", "/bin",
                "--proc", "/proc",
                "--dev", "/dev",
                "--tmpfs", "/tmp",
                "--chdir", "/tmp",
                "/bin/true",
            ],
            check=True,
            capture_output=True,
            timeout=5,
        )
        logger.info("bwrap available and functional")
        return True
    except Exception as exc:
        logger.warning("bwrap probe failed (%s) — sandbox profiles inactive", exc)
        return False


def _common(bwrap_bin: str) -> list[str]:
    return [
        bwrap_bin,
        "--die-with-parent",
        "--new-session",
        "--ro-bind",     "/usr", "/usr",
        "--ro-bind-try", "/bin", "/bin",
        "--ro-bind-try", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
        "--ro-bind-try", "/lib32", "/lib32",
        "--proc",        "/proc",
        "--ro-bind-try", "/sys", "/sys",
        "--dev",         "/dev",
        "--tmpfs",       "/tmp",
    ]


def build_argv(
    profile: str,
    *,
    working_dir: str | Path,
    ssh_dir: str | Path | None = None,
) -> list[str]:
    """
    Return the bwrap argument list for the named profile.

    The caller appends the command after this list:
        argv = build_argv("code-task", working_dir="/workspace") + ["bash", "-c", cmd]

    Returns an empty list if bwrap is unavailable — caller runs the command
    directly (SafePath still enforces filesystem scoping at the Python level).

    Parameters
    ----------
    profile:     One of PROFILES. Unknown names fall back to code-task.
    working_dir: The operator's project root. Bound rw (or ro for audit-task)
                 at the same absolute path inside the sandbox.
    ssh_dir:     Optional path to bind ro for deploy-task. Ignored by other
                 profiles.
    """
    if not bwrap_available():
        return []

    if profile not in PROFILES:
        logger.warning("Unknown sandbox profile %r — using code-task", profile)
        profile = _DEFAULT_PROFILE

    bwrap_bin = shutil.which("bwrap") or "bwrap"
    wd = str(Path(working_dir).resolve())
    argv = _common(bwrap_bin)

    if profile == "code-task":
        argv += [
            "--unshare-all",           # no network
            "--bind", wd, wd,          # project dir rw
            "--chdir", wd,
        ]

    elif profile == "deploy-task":
        argv += [
            "--unshare-pid",           # network on (no --unshare-net)
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-user",
            "--bind", wd, wd,
            "--chdir", wd,
        ]
        if ssh_dir:
            sd = str(Path(ssh_dir).resolve())
            argv += ["--ro-bind-try", sd, sd]

    elif profile == "audit-task":
        argv += [
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-user",
            "--ro-bind", wd, wd,       # read-only — no writes
            "--chdir", wd,
        ]

    elif profile == "open":
        argv += [
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-user",
            "--bind", wd, wd,
            "--chdir", wd,
        ]

    return argv
