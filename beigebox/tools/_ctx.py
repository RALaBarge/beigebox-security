"""
Per-run operator context.

Uses contextvars so each async operator session gets its own working_dir
without interfering with concurrent sessions or global config state.

Priority chain for working_dir:
  1. Contextvar set by operator.loop.run() for this session
  2. tools.fs.working_dir in config.yaml (global default)
  3. cwd at startup
"""

from __future__ import annotations

import contextvars
from pathlib import Path

_working_dir: contextvars.ContextVar[Path | None] = contextvars.ContextVar(
    "operator_working_dir", default=None
)


def set_working_dir(path: str | Path) -> None:
    _working_dir.set(Path(path).resolve())


def get_working_dir() -> Path:
    wd = _working_dir.get()
    if wd is not None:
        return wd
    try:
        from beigebox.config import get_config
        cfg_wd = get_config().get("tools", {}).get("fs", {}).get("working_dir", "")
        if cfg_wd:
            return Path(cfg_wd).resolve()
    except Exception:
        pass
    return Path.cwd()
