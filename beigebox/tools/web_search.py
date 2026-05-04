"""
DuckDuckGo web search via the public HTML endpoint.
Free, no API key required. Default search provider.

Replaces the previous `ddgs` package (which pulled in the precompiled
`primp` Rust TLS-fingerprint binary). This implementation hits
``https://html.duckduckgo.com/html/?q=<query>`` and extracts result
title / url / snippet via stdlib html.parser.

Note: ddgs supported features beyond plain query (region, safesearch
levels, timelimit, backend selection). The HTML endpoint exposes only
``q``, ``kl`` (region), and ``s`` (offset). The implementation honors
``max_results``; other ddgs-specific knobs are dropped.
"""

import logging
import urllib.parse
from html import unescape
from html.parser import HTMLParser

import httpx

logger = logging.getLogger(__name__)

_DDG_HTML_URL = "https://html.duckduckgo.com/html/"
_DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


class _DDGResultParser(HTMLParser):
    """Extract result blocks from DDG's HTML response.

    DDG renders each hit in this approximate shape:
        <div class="result results_links ...">
          <h2 class="result__title">
            <a class="result__a" href="https://...">Title text</a>
          </h2>
          <a class="result__snippet" href="...">Snippet text...</a>
        </div>

    We track:
      * the href of any tag with class containing "result__a" → url + start of title capture
      * data while inside that tag → title accumulator
      * the next "result__snippet" tag → snippet accumulator (data only)

    DDG's redirect URLs use the form ``//duckduckgo.com/l/?uddg=<encoded>``;
    we unwrap the ``uddg`` param when present.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.results: list[dict[str, str]] = []

        # Per-result state.
        self._cur_url: str = ""
        self._cur_title: list[str] = []
        self._cur_snippet: list[str] = []
        self._capturing_title: bool = False
        self._capturing_snippet: bool = False
        # We finalize a result when we see its snippet end (or the start of
        # the next result__a, whichever comes first).
        self._has_pending: bool = False

    @staticmethod
    def _has_class(attrs, classname: str) -> bool:
        for k, v in attrs:
            if k == "class" and v:
                return classname in v.split()
        return False

    @staticmethod
    def _attr(attrs, name: str) -> str | None:
        for k, v in attrs:
            if k == name:
                return v
        return None

    @staticmethod
    def _unwrap_ddg_redirect(url: str) -> str:
        """DDG wraps results in /l/?uddg=<encoded>; unwrap."""
        if not url:
            return url
        # Handle protocol-relative //duckduckgo.com/l/...
        if url.startswith("//"):
            url = "https:" + url
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.netloc.endswith("duckduckgo.com") and parsed.path.startswith("/l/"):
                qs = urllib.parse.parse_qs(parsed.query)
                target = qs.get("uddg", [None])[0]
                if target:
                    return urllib.parse.unquote(target)
        except Exception:
            pass
        return url

    def _flush_pending(self) -> None:
        if not self._has_pending:
            return
        title = " ".join("".join(self._cur_title).split())
        snippet = " ".join("".join(self._cur_snippet).split())
        url = self._cur_url
        if title and url:
            self.results.append({
                "title": unescape(title),
                "url": url,
                "snippet": unescape(snippet),
            })
        self._has_pending = False
        self._cur_url = ""
        self._cur_title = []
        self._cur_snippet = []

    def handle_starttag(self, tag, attrs):
        if tag == "a" and self._has_class(attrs, "result__a"):
            # New result begins — flush any prior one.
            self._flush_pending()
            href = self._attr(attrs, "href") or ""
            self._cur_url = self._unwrap_ddg_redirect(href)
            self._capturing_title = True
            self._has_pending = True
        elif tag == "a" and self._has_class(attrs, "result__snippet"):
            self._capturing_snippet = True
        # result__snippet sometimes appears as a <div>, not <a>, on
        # certain DDG variants. Handle both.
        elif tag in ("div", "span") and self._has_class(attrs, "result__snippet"):
            self._capturing_snippet = True

    def handle_endtag(self, tag):
        if tag == "a" and self._capturing_title:
            self._capturing_title = False
        elif self._capturing_snippet and tag in ("a", "div", "span"):
            self._capturing_snippet = False

    def handle_data(self, data):
        if self._capturing_title:
            self._cur_title.append(data)
        elif self._capturing_snippet:
            self._cur_snippet.append(data)

    def close(self):
        self._flush_pending()
        super().close()


def _parse_ddg_html(html: str, max_results: int) -> list[dict[str, str]]:
    parser = _DDGResultParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception as e:
        logger.debug("DDG HTML parse warning: %s", e)
    return parser.results[:max_results]


class WebSearchTool:
    """DuckDuckGo web search via the public HTML endpoint."""

    description = 'Search the web. input = plain search query string. Example: {"tool": "web_search", "input": "linux audio stacks ALSA PulseAudio 2024"}'

    # Class-level flags checked by operator._run_tool() via getattr to decide
    # whether to write the output to the blob store and how much to truncate
    # when injecting it back into the operator's context window.
    capture_tool_io: bool = True
    max_context_chars: int = 4000

    def __init__(self, max_results: int = 5):
        self.max_results = max_results
        logger.info("WebSearchTool initialized (max_results=%d)", max_results)

    def _search(self, query: str) -> list[dict[str, str]]:
        """POST to DDG's HTML endpoint and parse results.

        Uses POST (DDG's HTML form does this) and follows redirects;
        timeout 10s. Returns a list of {"title", "url", "snippet"} dicts.
        """
        try:
            resp = httpx.post(
                _DDG_HTML_URL,
                data={"q": query, "b": ""},
                headers=_DEFAULT_HEADERS,
                timeout=10.0,
                follow_redirects=True,
            )
            resp.raise_for_status()
        except Exception as e:
            logger.error("DDG fetch failed for '%s': %s", query, e)
            return []
        return _parse_ddg_html(resp.text, self.max_results)

    def run(self, query: str) -> str:
        """Execute a web search and return results as text."""
        try:
            results = self._search(query)
            if not results:
                return "No results found."
            lines = []
            for r in results:
                title = r.get("title", "")
                url = r.get("url", "")
                snippet = r.get("snippet", "")
                lines.append(f"[{title}]({url})\n{snippet}")
            return "\n\n".join(lines)
        except Exception as e:
            logger.error("Search failed for '%s': %s", query, e)
            return f"Search failed: {e}"
