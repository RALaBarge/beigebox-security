"""
Repo ingester plugin — clone a git repo and ingest all source files into vector memory.

Usage (operator tool input):
    https://github.com/anomalyco/opencode

Config in config.yaml:
    tools:
      plugins:
        enabled: true
        repo_ingester:
          enabled: true
          max_file_chars: 16000
          chunk_size: 800
          chunk_overlap: 80
          extensions:
            - .rs
            - .ts
            - .js
            - .md
            - .json
            - .toml
            - .yaml
            - .sh
"""

import hashlib
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

PLUGIN_NAME = "repo_ingester"
PLUGIN_Z_ALIASES = {
    "ingest": "repo_ingester",
    "clone": "repo_ingester",
}

_APP_ROOT = Path(__file__).parent.parent
_WORKSPACE_OUT = _APP_ROOT / "workspace" / "out"

_DEFAULT_EXTENSIONS = {".rs", ".ts", ".js", ".md", ".json", ".toml", ".yaml", ".sh", ".py"}


def _plugin_cfg() -> dict:
    try:
        from beigebox.config import get_config
        return get_config().get("tools", {}).get("plugins", {}).get("repo_ingester", {})
    except Exception:
        return {}


def _chunk(text: str, chunk_size: int, overlap: int) -> list[str]:
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        segment = text[start:end]
        if end < len(text):
            break_at = segment.rfind("\n\n", int(chunk_size * 0.8))
            if break_at != -1:
                end = start + break_at + 2
        chunks.append(text[start:end].strip())
        start = end - overlap if end - overlap > start else end
    return [c for c in chunks if c]


def _ingest_chunks(chunks: list[str], source: str) -> int:
    try:
        from beigebox.config import get_config, get_primary_backend_url, get_storage_paths
        from beigebox.storage.backends import build_backend_kwargs, make_backend
        from beigebox.storage.vector_store import VectorStore

        cfg = get_config()
        embed_cfg = cfg.get("embedding", {})
        _, vector_path = get_storage_paths(cfg)
        embedding_model = embed_cfg.get("model", "nomic-embed-text")
        embedding_url = embed_cfg.get("backend_url") or get_primary_backend_url(cfg)

        backend_type, backend_kwargs = build_backend_kwargs(cfg, vector_path)
        backend = make_backend(backend_type, **backend_kwargs)
        store = VectorStore(
            embedding_model=embedding_model,
            embedding_url=embedding_url,
            backend=backend,
        )
        src_hash = hashlib.sha256(source.encode()).hexdigest()[:16]

        for i, chunk in enumerate(chunks):
            store.store_document_chunk(
                source_file=source,
                chunk_index=i,
                char_offset=0,
                blob_hash=src_hash,
                text=chunk,
            )
        return len(chunks)
    except Exception as e:
        logger.error("repo_ingester: vector ingest failed: %s", e, exc_info=True)
        return 0


class RepoIngesterTool:
    description = 'Clone a git repo and ingest source files into vector memory. input = git URL. Example: {"tool": "repo_ingester", "input": "https://github.com/anomalyco/opencode"}'

    def run(self, query: str) -> str:
        query = query.strip().strip("'\"")
        if not query:
            return "Usage: provide a git repo URL (e.g. https://github.com/anomalyco/opencode)"

        cfg = _plugin_cfg()
        max_file_chars = int(cfg.get("max_file_chars", 16000))
        chunk_size = int(cfg.get("chunk_size", 800))
        overlap = int(cfg.get("chunk_overlap", 80))
        extensions = set(cfg.get("extensions", list(_DEFAULT_EXTENSIONS)))

        repo_name = query.rstrip("/").split("/")[-1]
        logger.info("repo_ingester: cloning %s", query)

        with tempfile.TemporaryDirectory(prefix="repo_ingest_") as tmpdir:
            try:
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", query, tmpdir],
                    capture_output=True, text=True, timeout=120,
                )
                if result.returncode != 0:
                    return f"git clone failed:\n{result.stderr[:500]}"
            except subprocess.TimeoutExpired:
                return "git clone timed out after 120s"
            except FileNotFoundError:
                return "git not found in container"

            logger.info("repo_ingester: cloned, walking files...")

            total_chunks = 0
            total_files = 0
            skipped = 0
            results = []

            for root, dirs, files in os.walk(tmpdir):
                dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules", "target")]
                for fname in files:
                    ext = Path(fname).suffix.lower()
                    if ext not in extensions:
                        continue

                    fpath = Path(root) / fname
                    rel = str(fpath.relative_to(tmpdir))
                    if fpath.stat().st_size > max_file_chars * 2:
                        skipped += 1
                        continue

                    try:
                        text = fpath.read_text(encoding="utf-8", errors="replace")
                    except Exception:
                        skipped += 1
                        continue

                    if not text.strip():
                        continue
                    if len(text) > max_file_chars:
                        text = text[:max_file_chars]

                    chunks = _chunk(text, chunk_size, overlap)
                    source_ref = f"{repo_name}:{rel}"
                    n = _ingest_chunks(chunks, source_ref)
                    total_chunks += n
                    total_files += 1
                    results.append(f"  {rel}: {n} chunks")

                    if total_files % 50 == 0:
                        logger.info("repo_ingester: %d files processed (%d chunks)", total_files, total_chunks)

            out = [
                f"# Repo: {query}",
                f"*{total_files} files ingested, {total_chunks} total chunks*",
                f"*{skipped} files skipped (binary/too large)*",
                "",
                "## Files ingested:",
            ] + results[-20:] + [
                "",
                "Searchable via document_search / memory tools.",
            ]

            report = "\n".join(out)
            safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', repo_name)[:60]
            out_path = _WORKSPACE_OUT / f"repo_{safe_name}.txt"
            try:
                _WORKSPACE_OUT.mkdir(parents=True, exist_ok=True)
                out_path.write_text(report, encoding="utf-8")
            except Exception:
                pass

            return report