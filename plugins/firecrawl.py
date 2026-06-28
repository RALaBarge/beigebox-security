"""
Firecrawl tool — crawl entire documentation sites and ingest into vector memory.

Uses Firecrawl API to crawl a URL, extract all pages as Markdown, and index
them into the vector store for semantic search.

Requires: FIRECRAWL_API_KEY env var set.

Usage (operator tool input):
    https://opencode.ai/docs

Config in config.yaml:
    tools:
      plugins:
        enabled: true
        firecrawl:
          enabled: true
          max_pages: 100
          max_ref_tokens: 8000
          chunk_size: 800
          chunk_overlap: 80
"""

import hashlib
import logging
import os
import re
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

PLUGIN_NAME = "firecrawl"
PLUGIN_Z_ALIASES = {
    "crawl": "firecrawl",
    "firecrawl": "firecrawl",
    "site": "firecrawl",
}

_APP_ROOT      = Path(__file__).parent.parent
_WORKSPACE_OUT = _APP_ROOT / "workspace" / "out"

_CHARS_PER_TOKEN = 4

_FIRECRAWL_BASE = "https://api.firecrawl.dev/v1"


def _plugin_cfg() -> dict:
    try:
        from beigebox.config import get_config
        return get_config().get("tools", {}).get("plugins", {}).get("firecrawl", {})
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
        logger.debug("firecrawl: vector ingest skipped: %s", e)
        return 0


class FirecrawlTool:
    description = 'Crawl a documentation site via Firecrawl and index all pages into vector memory. input = root URL. Example: {"tool": "firecrawl", "input": "https://opencode.ai/docs"}'

    def run(self, query: str) -> str:
        query = query.strip().strip("'\"")
        if not query:
            return "Usage: provide a URL to crawl (e.g. https://opencode.ai/docs)"

        if not query.startswith(("http://", "https://")):
            return f"Invalid URL: {query}"

        api_key = os.environ.get("FIRECRAWL_API_KEY")
        if not api_key:
            return "Firecrawl requires FIRECRAWL_API_KEY env var. Get one at https://firecrawl.dev"

        cfg = _plugin_cfg()
        max_pages = int(cfg.get("max_pages", 100))
        max_tokens = int(cfg.get("max_ref_tokens", 8000))
        chunk_size = int(cfg.get("chunk_size", 800))
        overlap = int(cfg.get("chunk_overlap", 80))
        max_chars = max_tokens * _CHARS_PER_TOKEN

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        logger.info("firecrawl: crawling %s (max %d pages)", query, max_pages)

        try:
            crawl_resp = httpx.post(
                f"{_FIRECRAWL_BASE}/crawl",
                headers=headers,
                json={
                    "url": query,
                    "limit": max_pages,
                    "scrapeOptions": {
                        "formats": ["markdown"],
                        "onlyMainContent": True,
                    },
                },
                timeout=30.0,
            )
            crawl_resp.raise_for_status()
            crawl_data = crawl_resp.json()

            job_id = crawl_data.get("id")
            if not job_id:
                return f"Firecrawl did not return a job ID: {crawl_data}"

            import time
            result_url = f"{_FIRECRAWL_BASE}/crawl/{job_id}"

            all_text = []
            page_count = 0
            for attempt in range(60):
                time.sleep(5)
                status_resp = httpx.get(result_url, headers=headers, timeout=30.0)
                status_resp.raise_for_status()
                status_data = status_resp.json()

                data = status_data.get("data", [])
                for page in data:
                    md = page.get("markdown", "") or page.get("content", "") or ""
                    source_url = page.get("metadata", {}).get("sourceURL", query)
                    all_text.append(f"# Source: {source_url}\n\n{md}")
                    page_count += 1

                status = status_data.get("status")
                if status == "completed":
                    break
                if status == "failed":
                    return f"Firecrawl crawl failed: {status_data}"

            if not all_text:
                return f"Firecrawl returned no pages for {query}"

            combined = "\n\n---\n\n".join(all_text)

            chunks = _chunk(combined, chunk_size, overlap)
            n_ingested = _ingest_chunks(chunks, query)
            if n_ingested:
                logger.info("firecrawl: ingested %d chunks from %d pages (%s)", n_ingested, page_count, query)

            safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', query.split("//")[-1].rstrip("/"))[:60]
            out_path = _WORKSPACE_OUT / f"crawl_{safe_name}.md"
            saved_to = None
            try:
                _WORKSPACE_OUT.mkdir(parents=True, exist_ok=True)
                out_path.write_text(combined, encoding="utf-8")
                saved_to = out_path
            except Exception as e:
                logger.debug("firecrawl: could not save: %s", e)

            truncated = False
            if len(combined) > max_chars:
                combined = combined[:max_chars]
                truncated = True

            header = f"# Crawl: {query}\n*{page_count} pages, {n_ingested} chunks ingested*\n"
            if saved_to:
                header += f"*Full crawl saved to workspace/out/{saved_to.name}*\n"
            header += "\n"

            footer = ""
            if truncated:
                footer = f"\n\n*… truncated at ~{max_tokens} tokens*"

            return header + combined + footer

        except httpx.HTTPStatusError as e:
            return f"Firecrawl HTTP {e.response.status_code}: {e.response.text[:500]}"
        except Exception as e:
            return f"Firecrawl error: {e}"