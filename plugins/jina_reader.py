"""
Jina Reader plugin — fetch any URL as clean Markdown via r.jina.ai.

No API key needed for basic usage. The Jina Reader service converts any URL
to clean, LLM-friendly Markdown. After fetching, content is chunked and
ingested into the vector store for semantic search via document_search / memory.

Usage (operator tool input):
    https://opencode.ai/docs
    https://opencode.ai/docs/config/
    https://opencode.ai/docs/providers/

Config in config.yaml:
    tools:
      plugins:
        enabled: true
        jina_reader:
          enabled: true
          max_ref_tokens: 8000
          chunk_size: 800
          chunk_overlap: 80
"""

import hashlib
import logging
import re
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

PLUGIN_NAME = "jina_reader"
PLUGIN_Z_ALIASES = {
    "jina": "jina_reader",
    "read": "jina_reader",
    "fetch": "jina_reader",
}

_APP_ROOT      = Path(__file__).parent.parent
_WORKSPACE_OUT = _APP_ROOT / "workspace" / "out"

_CHARS_PER_TOKEN = 4

_JINA_BASE = "https://r.jina.ai"
_DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Accept": "text/plain",
}


def _plugin_cfg() -> dict:
    try:
        from beigebox.config import get_config
        return get_config().get("tools", {}).get("plugins", {}).get("jina_reader", {})
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
        logger.error("jina_reader: vector ingest failed: %s", e, exc_info=True)
        return 0


class JinaReaderTool:
    description = 'Fetch a URL as clean Markdown via Jina Reader and index it in vector memory. input = URL. Example: {"tool": "jina_reader", "input": "https://opencode.ai/docs"}'

    def run(self, query: str) -> str:
        query = query.strip().strip("'\"")
        if not query:
            return "Usage: provide a URL to fetch (e.g. https://opencode.ai/docs)"

        if not query.startswith(("http://", "https://")):
            return f"Invalid URL: {query}. Must start with http:// or https://"

        cfg = _plugin_cfg()
        max_tokens = int(cfg.get("max_ref_tokens", 8000))
        chunk_size = int(cfg.get("chunk_size", 800))
        overlap = int(cfg.get("chunk_overlap", 80))
        max_chars = max_tokens * _CHARS_PER_TOKEN

        jina_url = f"{_JINA_BASE}/{query}"
        logger.info("jina_reader: fetching %s", jina_url)

        try:
            resp = httpx.get(jina_url, headers=_DEFAULT_HEADERS, timeout=60.0)
            resp.raise_for_status()
            text = resp.text
        except httpx.HTTPStatusError as e:
            return f"Jina Reader returned HTTP {e.response.status_code} for {query}"
        except httpx.TimeoutException:
            return f"Jina Reader timed out after 60s for {query}"
        except Exception as e:
            return f"Jina Reader error: {e}"

        if not text.strip():
            return f"Jina Reader returned empty content for {query}"

        # Ingest into vector store
        chunks = _chunk(text, chunk_size, overlap)
        n_ingested = _ingest_chunks(chunks, query)
        if n_ingested:
            logger.info("jina_reader: ingested %d chunks from %s", n_ingested, query)

        # Save to workspace/out/
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', query.split("//")[-1].rstrip("/"))[:100]
        out_path = _WORKSPACE_OUT / f"{safe_name}.md"
        saved_to = None
        try:
            _WORKSPACE_OUT.mkdir(parents=True, exist_ok=True)
            out_path.write_text(text, encoding="utf-8")
            saved_to = out_path
        except Exception as e:
            logger.debug("jina_reader: could not save to workspace/out: %s", e)

        truncated = False
        if len(text) > max_chars:
            text = text[:max_chars]
            truncated = True

        header = f"# {query}\n"
        if n_ingested:
            header += f"*({n_ingested} chunks ingested into memory — searchable via document_search / memory)*\n"
        if saved_to:
            header += f"*Full text saved to workspace/out/{saved_to.name}*\n"
        header += "\n"

        footer = ""
        if truncated:
            footer = f"\n\n*… truncated at ~{max_tokens} tokens. Full text saved to workspace/out/{out_path.name}*"

        return header + text + footer