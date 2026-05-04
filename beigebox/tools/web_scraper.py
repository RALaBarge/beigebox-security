"""
Web scraper: fetch a URL and extract clean text content.
Uses httpx + stdlib html.parser. No API key needed.

On every successful fetch:
  1. Saves the raw HTML to <save_dir>/scraped/<domain>_<timestamp>.html
     for permanent, re-parseable storage.
  2. Embeds the extracted text into the vector store (if one is configured)
     so scraped content is searchable via /beigebox/search.
"""

import hashlib
import ipaddress
import logging
import os
import re
import urllib.parse
from datetime import datetime, timezone
from html import unescape
from html.parser import HTMLParser

import httpx

logger = logging.getLogger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
}

# Chunk size for RAG embedding — keeps each chunk within typical embedding limits.
_CHUNK_CHARS = 1500

# Tags whose subtree we drop entirely — script/style and chrome elements.
# Matches the previous bs4 .decompose() set.
_SKIP_TAGS = frozenset({"script", "style", "nav", "footer", "header", "aside", "noscript"})

# Block-level tags after whose end-tag we emit a newline so the subsequent
# whitespace collapse keeps text on its own line — mimics bs4's
# get_text(separator="\n") "every block on a fresh line" behavior.
_BLOCK_TAGS = frozenset({
    "p", "div", "br", "li", "ul", "ol", "tr", "td", "th", "table",
    "h1", "h2", "h3", "h4", "h5", "h6", "section", "article",
    "blockquote", "pre", "hr", "figure", "figcaption", "main",
})


class _TextExtractor(HTMLParser):
    """Stdlib HTMLParser subclass that mirrors the previous bs4 extraction.

    Preserves:
      * decompose-equivalent: drop subtree of script/style/nav/footer/header/aside/noscript.
      * get_text(separator="\\n"): emit \\n between block-level elements.
      * resilience: convert_charrefs=True handles entity decoding; malformed
        HTML is best-effort (HTMLParser is lenient by default).
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        # Stack of currently open tags. We push on every starttag and pop on
        # the matching endtag. We *also* tolerate void elements (br, hr, img,
        # etc.) — handle_startendtag is called for those and we never push.
        self._stack: list[str] = []
        # Count of currently-open _SKIP_TAGS ancestors. While >0 we drop data.
        self._skip_depth: int = 0
        self._chunks: list[str] = []

    # --- tag handling ------------------------------------------------------

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        self._stack.append(tag)
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
        # <br> is special-cased: real-world HTML often emits <br> as a start
        # tag without a self-close — treat it as a line break unconditionally.
        if tag == "br" and self._skip_depth == 0:
            self._chunks.append("\n")

    def handle_startendtag(self, tag: str, attrs) -> None:
        # Void / self-closed elements (e.g. <br/>, <hr/>, <img/>).
        tag = tag.lower()
        if tag == "br" and self._skip_depth == 0:
            self._chunks.append("\n")
        elif tag in _BLOCK_TAGS and self._skip_depth == 0:
            self._chunks.append("\n")
        # Don't push to the stack — there's no matching endtag.

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        # Pop until we find a matching open tag (forgiving of mismatched
        # nesting in the wild). If we never find it, leave stack alone.
        if tag in self._stack:
            while self._stack:
                popped = self._stack.pop()
                if popped in _SKIP_TAGS:
                    self._skip_depth = max(0, self._skip_depth - 1)
                if popped == tag:
                    break
        if tag in _BLOCK_TAGS and self._skip_depth == 0:
            self._chunks.append("\n")

    # --- data handling -----------------------------------------------------

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0:
            return
        self._chunks.append(data)

    # --- result ------------------------------------------------------------

    def get_text(self) -> str:
        # Join, then collapse: strip every line, drop blank lines, rejoin
        # with single \n. Matches the previous bs4 cleanup pass.
        raw = "".join(self._chunks)
        # convert_charrefs handles most entities, but be defensive.
        raw = unescape(raw)
        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        return "\n".join(lines)


def _extract_text_from_html(html: str) -> str:
    """Mirror of the previous bs4 path: strip script/style/chrome, get text, collapse."""
    parser = _TextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception as e:
        # html.parser is lenient — but be paranoid about pathological input.
        logger.debug("HTML parse warning: %s", e)
    return parser.get_text()


class WebScraperTool:
    """Fetch a URL, return clean text, save raw HTML, and embed into RAG."""

    description = 'Fetch and read a webpage. input = full URL. Example: {"tool": "web_scraper", "input": "https://example.com/page"}'

    capture_tool_io: bool = True
    max_context_chars: int = 6000

    def __init__(
        self,
        max_content_length: int = 10000,
        save_dir: str | None = None,
        vector_store=None,
    ):
        self.max_content_length = max_content_length
        self._save_dir = save_dir
        self._vector_store = vector_store
        logger.info(
            "WebScraperTool initialized (max_chars=%d, save_dir=%s, rag=%s)",
            max_content_length,
            save_dir or "disabled",
            vector_store is not None,
        )

    def _validate_url(self, url: str) -> str | None:
        """Return error string if URL is disallowed, else None."""
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            return "invalid URL"
        if parsed.scheme not in ("http", "https"):
            return f"scheme '{parsed.scheme}' not allowed (http/https only)"
        host = parsed.hostname or ""
        # Block localhost and loopback
        if host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost"):
            return "private/localhost addresses not allowed"
        # Block private IP ranges
        try:
            addr = ipaddress.ip_address(host)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                return f"private IP address not allowed: {host}"
        except ValueError:
            pass  # hostname, not a raw IP — allow
        # Block cloud metadata endpoints
        if re.search(r"169\.254\.\d+\.\d+", host):
            return "link-local/metadata addresses not allowed"
        return None

    def _save_html(self, url: str, html: str) -> str | None:
        """Write raw HTML to <save_dir>/scraped/ and return the file path."""
        if not self._save_dir:
            return None
        try:
            scraped_dir = os.path.join(self._save_dir, "scraped")
            os.makedirs(scraped_dir, exist_ok=True)
            parsed = urllib.parse.urlparse(url)
            # Build a safe filename from the domain + path, capped at 80 chars.
            slug = re.sub(r"[^\w\-]", "_", f"{parsed.netloc}{parsed.path}")[:80]
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            filename = f"{slug}_{ts}.html"
            filepath = os.path.join(scraped_dir, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html)
            logger.debug("Saved raw HTML → %s", filepath)
            return filepath
        except Exception as e:
            logger.warning("Failed to save raw HTML for %s: %s", url, e)
            return None

    def _embed_text(self, url: str, text: str, filepath: str | None) -> None:
        """Chunk text and embed into the vector store for RAG search."""
        if not self._vector_store or not text.strip():
            return
        try:
            blob_hash = hashlib.sha256(text.encode()).hexdigest()
            source = filepath or url
            chunks = [
                text[i : i + _CHUNK_CHARS]
                for i in range(0, len(text), _CHUNK_CHARS)
            ]
            for idx, chunk in enumerate(chunks):
                self._vector_store.store_document_chunk(
                    source_file=source,
                    chunk_index=idx,
                    char_offset=idx * _CHUNK_CHARS,
                    blob_hash=blob_hash,
                    text=chunk,
                )
            logger.debug("Embedded %d chunk(s) from %s", len(chunks), url)
        except Exception as e:
            logger.warning("RAG embed failed for %s: %s", url, e)

    def run(self, url: str) -> str:
        """Fetch URL, extract text, save HTML, embed into RAG."""
        err = self._validate_url(url)
        if err:
            logger.warning("WebScraperTool blocked URL %s: %s", url, err)
            return f"Blocked: {err}"
        try:
            # follow_redirects=True matches the requests default behavior.
            resp = httpx.get(
                url,
                headers=DEFAULT_HEADERS,
                timeout=15,
                follow_redirects=True,
            )
            resp.raise_for_status()

            raw_html = resp.text
            text = _extract_text_from_html(raw_html)

            # Save raw HTML (preserves original structure, evergreen format)
            filepath = self._save_html(url, raw_html)

            # Embed extracted text into vector store for RAG
            self._embed_text(url, text, filepath)

            if len(text) > self.max_content_length:
                text = text[: self.max_content_length] + "\n\n[... truncated]"

            logger.debug("Scraped %d chars from %s", len(text), url)
            return text

        except Exception as e:
            logger.error("Scrape failed for %s: %s", url, e)
            return f"Failed to scrape {url}: {e}"
