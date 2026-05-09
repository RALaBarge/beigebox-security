"""
Backend plugin auto-discovery and registration.

Loads custom `BaseBackend` subclasses from a plugins directory. Plugins are
operator-trusted code (see `BEIGEBOX_IS_NOT.md`, "Plugin model") — this
loader does not sandbox them. Two defenses-in-depth do apply:

  1. The plugins directory must be under the project root and not
     world-writable (`beigebox.security.plugin_safety.safe_plugin_dir`).
  2. Only files whose stem is listed in `backend_plugins.allowed` (config.yaml)
     are loaded. Without that key, the loader logs a deprecation warning and
     loads everything (backwards compat for one release).

Operator workflow to add a new plugin:
  1. Drop the .py into `backends/plugins/`.
  2. Add the file's stem to `backend_plugins.allowed` in `config.yaml`.

Example: `backends/plugins/llama_cpp.py` → `backend_plugins.allowed: [llama_cpp]`.
"""

import importlib.util
import logging
import re
from pathlib import Path

from beigebox.backends.base import BaseBackend
from beigebox.security.plugin_safety import (
    UnsafePluginDirError,
    filter_by_allowlist,
    safe_plugin_dir,
)

logger = logging.getLogger(__name__)

# beigebox/backends/plugin_loader.py → parent.parent.parent = project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def load_backend_plugins(
    plugins_dir: str = "backends/plugins",
    cfg: dict | None = None,
) -> dict[str, type[BaseBackend]]:
    """
    Discover and load custom backend implementations.

    Args:
        plugins_dir: Directory to scan, relative to project root or absolute.
        cfg: Full BeigeBox config dict. Reads `backend_plugins.allowed` for the
            allow-list. If None or the key is missing, falls back to
            load-everything with a deprecation warning.

    Returns:
        Dict mapping provider name (snake_case of class name minus "Backend")
        → backend class.
    """
    plugins: dict[str, type[BaseBackend]] = {}

    try:
        base = safe_plugin_dir(plugins_dir, project_root=_PROJECT_ROOT)
    except UnsafePluginDirError as e:
        logger.error("Refusing to load backend plugins: %s", e)
        return plugins

    if base is None:
        return plugins

    bp_cfg = (cfg or {}).get("backend_plugins") or {}
    allowed = bp_cfg.get("allowed")  # None | list[str]

    candidates = sorted(p for p in base.glob("*.py") if not p.name.startswith("_"))
    for py_file in filter_by_allowlist(candidates, allowed, context="backend_plugin"):
        try:
            spec = importlib.util.spec_from_file_location(
                f"beigebox.backends.plugins.{py_file.stem}",
                py_file,
            )
            if not spec or not spec.loader:
                logger.warning("Could not load spec for %s", py_file)
                continue

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BaseBackend)
                    and attr is not BaseBackend
                ):
                    provider_name = _camel_to_snake(attr.__name__.replace("Backend", ""))
                    plugins[provider_name] = attr
                    logger.info(
                        "Loaded backend plugin: %s (%s)", provider_name, attr.__name__
                    )
        except Exception as e:
            logger.error("Failed to load backend plugin from %s: %s", py_file, e)

    return plugins


def _camel_to_snake(name: str) -> str:
    """Convert CamelCase to snake_case."""
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()
