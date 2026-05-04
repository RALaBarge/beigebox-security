"""
VectorStore — embedding + semantic search facade.

Owns all embedding logic (calling Ollama's /api/embed endpoint).
Delegates raw vector storage to a pluggable VectorBackend.

The backend is configured via  storage.vector_backend  in config.yaml
(default: "postgres"; "memory" is available for tests/ephemeral runs).
All callers outside this module are unchanged — they still instantiate
VectorStore and call store_message / search / search_grouped / get_stats.

To add a new vector database:
  1. Implement VectorBackend in beigebox/storage/backends/<n>.py
  2. Register it in beigebox/storage/backends/__init__.py
  3. Set  storage.vector_backend: <n>  in config.yaml
"""

import logging
from datetime import datetime, timezone

import httpx

from beigebox.storage.backends import VectorBackend
from beigebox.security.rag_poisoning_detector import RAGPoisoningDetector

logger = logging.getLogger(__name__)


class VectorStore:
    """
    Embedding + semantic search facade over a pluggable VectorBackend.

    Embedding stays here; the backend only sees raw vectors.
    """

    def __init__(
        self,
        embedding_model: str,
        embedding_url: str,
        # Backend wiring — callers pass these through from config
        backend: VectorBackend | None = None,
        poisoning_detector: RAGPoisoningDetector | None = None,
        quarantine = None,  # Optional QuarantineRepo for poisoning quarantine logging
    ):
        self.embedding_model = embedding_model
        self.embedding_url = embedding_url.rstrip("/")
        self.poisoning_detector = poisoning_detector
        self.quarantine = quarantine

        if backend is None:
            raise ValueError(
                "VectorStore requires a 'backend' instance. Build one with "
                "beigebox.storage.backends.make_backend('postgres', ...) or "
                "make_backend('memory') for tests."
            )
        self._backend = backend

        logger.info(
            "VectorStore initialised (backend=%s, model=%s, quarantine=%s)",
            type(self._backend).__name__,
            self.embedding_model,
            "enabled" if quarantine else "disabled",
        )

    # ------------------------------------------------------------------
    # Embedding helpers
    # ------------------------------------------------------------------

    def _get_embedding(self, text: str) -> list[float]:
        """Get embedding vector from Ollama API (sync)."""
        try:
            resp = httpx.post(
                f"{self.embedding_url}/api/embed",
                json={"model": self.embedding_model, "input": text},
                timeout=30.0,
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise RuntimeError(
                    f"Embedding model '{self.embedding_model}' not found — "
                    f"run: ollama pull {self.embedding_model}"
                ) from e
            raise
        try:
            data = resp.json()
        except Exception as e:
            raise RuntimeError(
                f"Embedding endpoint returned non-JSON response: {resp.text[:200]}"
            ) from e
        embeddings = data.get("embeddings")
        if not embeddings or not embeddings[0]:
            raise RuntimeError(
                f"Embedding model '{self.embedding_model}' returned an empty embeddings "
                f"array — input may be blank or the model may have failed silently."
            )
        return embeddings[0]

    async def _get_embedding_async(self, text: str) -> list[float]:
        """Get embedding vector from Ollama API (async)."""
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(
                    f"{self.embedding_url}/api/embed",
                    json={"model": self.embedding_model, "input": text},
                    timeout=30.0,
                )
                resp.raise_for_status()
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    raise RuntimeError(
                        f"Embedding model '{self.embedding_model}' not found — "
                        f"run: ollama pull {self.embedding_model}"
                    ) from e
                raise
            try:
                data = resp.json()
            except Exception as e:
                raise RuntimeError(
                    f"Embedding endpoint returned non-JSON response: {resp.text[:200]}"
                ) from e
            embeddings = data.get("embeddings")
            if not embeddings or not embeddings[0]:
                raise RuntimeError(
                    f"Embedding model '{self.embedding_model}' returned an empty embeddings "
                    f"array — input may be blank or the model may have failed silently."
                )
            return embeddings[0]

    # ------------------------------------------------------------------
    # Public API — unchanged from previous VectorStore
    # ------------------------------------------------------------------

    def store_message(
        self,
        message_id: str,
        conversation_id: str,
        role: str,
        content: str,
        model: str = "",
        timestamp: str = "",
    ):
        """Embed and store a message (sync, for background tasks)."""
        if not content.strip():
            return
        try:
            embedding = self._get_embedding(content)
            # Check for poisoned embeddings
            if self.poisoning_detector:
                is_poisoned, confidence, reason = self.poisoning_detector.is_poisoned(embedding)
                if is_poisoned and confidence > 0.8:
                    logger.warning("POISONED embedding detected [%s]: %s (confidence=%.2f)", message_id, reason, confidence)
                    if self.quarantine:
                        self.quarantine.log(
                            document_id=message_id,
                            embedding=embedding,
                            confidence=confidence,
                            reason=reason,
                            method="magnitude",
                        )
                    return  # silently reject
                elif is_poisoned and confidence > 0.5:
                    logger.warning("SUSPICIOUS embedding [%s]: %s (confidence=%.2f)", message_id, reason, confidence)
                    if self.quarantine:
                        self.quarantine.log(
                            document_id=message_id,
                            embedding=embedding,
                            confidence=confidence,
                            reason=reason,
                            method="magnitude",
                        )
                    # Continue anyway (warn mode)
            self._backend.upsert(
                ids=[message_id],
                embeddings=[embedding],
                documents=[content],
                metadatas=[{
                    "conversation_id": conversation_id,
                    "role": role,
                    "model": model,
                    "timestamp": timestamp,
                }],
            )
            logger.debug("Embedded message %s", message_id)
        except Exception as e:
            logger.error("Failed to embed message %s: %s", message_id, e)

    async def store_message_async(
        self,
        message_id: str,
        conversation_id: str,
        role: str,
        content: str,
        model: str = "",
        timestamp: str = "",
    ):
        """Embed and store a message (async, for the request pipeline)."""
        if not content.strip():
            return
        try:
            embedding = await self._get_embedding_async(content)
            # Check for poisoned embeddings
            if self.poisoning_detector:
                is_poisoned, confidence, reason = self.poisoning_detector.is_poisoned(embedding)
                if is_poisoned and confidence > 0.8:
                    logger.warning("POISONED embedding detected [%s]: %s (confidence=%.2f)", message_id, reason, confidence)
                    if self.quarantine:
                        self.quarantine.log(
                            document_id=message_id,
                            embedding=embedding,
                            confidence=confidence,
                            reason=reason,
                            method="magnitude",
                        )
                    return  # silently reject
                elif is_poisoned and confidence > 0.5:
                    logger.warning("SUSPICIOUS embedding [%s]: %s (confidence=%.2f)", message_id, reason, confidence)
                    if self.quarantine:
                        self.quarantine.log(
                            document_id=message_id,
                            embedding=embedding,
                            confidence=confidence,
                            reason=reason,
                            method="magnitude",
                        )
                    # Continue anyway (warn mode)
            self._backend.upsert(
                ids=[message_id],
                embeddings=[embedding],
                documents=[content],
                metadatas=[{
                    "conversation_id": conversation_id,
                    "role": role,
                    "model": model,
                    "timestamp": timestamp,
                }],
            )
            logger.debug("Embedded message %s", message_id)
        except Exception as e:
            logger.error("Failed to embed message %s: %s", message_id, e)

    def search(
        self,
        query: str,
        n_results: int = 5,
        role_filter: str | None = None,
        where: dict | None = None,
    ) -> list[dict]:
        """Semantic search over stored messages."""
        try:
            embedding = self._get_embedding(query)
        except Exception as e:
            logger.error("search: failed to embed query: %s", e)
            return []

        # Merge role_filter into where clause if provided
        if role_filter and not where:
            where = {"role": role_filter}
        elif role_filter and where:
            where["role"] = role_filter

        results = self._backend.query(embedding, n_results=n_results, where=where)

        out: list[dict] = []
        for i in range(len(results["ids"][0])):
            content = results["documents"][0][i]
            metadata = results["metadatas"][0][i]
            if not self._verify_doc_chunk(content, metadata):
                continue  # dropped — wire event already emitted
            out.append({
                "id":       results["ids"][0][i],
                "content":  content,
                "metadata": metadata,
                "distance": results["distances"][0][i],
            })
        return out

    def search_grouped(
        self,
        query: str,
        n_conversations: int = 5,
        candidates: int = 40,
        role_filter: str | None = None,
    ) -> list[dict]:
        """
        Semantic search grouped by conversation.

        Two-pass:
          1. Retrieve `candidates` message-level hits.
          2. Group by conversation_id, keep best (lowest distance) hit per
             conversation, sort by score, return top n_conversations.

        candidates >> n_conversations because a long conversation may contribute
        many message-level hits — without the overfetch, a single very active
        conversation could dominate the top-K and crowd out other conversations.
        """
        try:
            embedding = self._get_embedding(query)
        except Exception as e:
            logger.error("search_grouped: failed to embed query: %s", e)
            return []

        where = {"role": role_filter} if role_filter else None
        fetch_n = min(max(candidates, n_conversations * 8), 200)
        results = self._backend.query(embedding, n_results=fetch_n, where=where)

        groups: dict[str, dict] = {}
        for i in range(len(results["ids"][0])):
            meta    = results["metadatas"][0][i]
            conv_id = meta.get("conversation_id", "")
            if not conv_id:
                continue
            distance = results["distances"][0][i]
            score    = max(0.0, round(1.0 - distance, 4))
            content  = results["documents"][0][i] or ""

            if conv_id not in groups:
                groups[conv_id] = {
                    "conversation_id": conv_id,
                    "score":           score,
                    "excerpt":         content[:300],
                    "role":            meta.get("role", ""),
                    "model":           meta.get("model", ""),
                    "timestamp":       meta.get("timestamp", ""),
                    "match_count":     1,
                }
            else:
                groups[conv_id]["match_count"] += 1
                if score > groups[conv_id]["score"]:
                    groups[conv_id].update({
                        "score":     score,
                        "excerpt":   content[:300],
                        "role":      meta.get("role", ""),
                        "model":     meta.get("model", ""),
                        "timestamp": meta.get("timestamp", ""),
                    })

        ranked = sorted(groups.values(), key=lambda x: x["score"], reverse=True)
        return ranked[:n_conversations]

    def store_tool_result(
        self,
        session_id: str,
        tool_name: str,
        tool_input: str,
        blob_hash: str,
        preview: str,
        timestamp: str,
    ) -> None:
        """Embed and store a tool I/O record from an operator session."""
        if not preview.strip():
            return
        try:
            embedding = self._get_embedding(preview)
            # ID format encodes session, tool, and timestamp so each tool call
            # gets a unique deterministic key. Upserting with the same key is
            # safe (idempotent) in case of retry.
            entry_id = f"tool_{session_id}_{tool_name}_{timestamp}"
            self._backend.upsert(
                ids=[entry_id],
                embeddings=[embedding],
                documents=[preview],
                metadatas=[{
                    # source_type distinguishes tool results, document chunks, and
                    # conversation messages within the shared vector collection.
                    # Missing-key exclusion means older entries (no source_type)
                    # are simply excluded from filtered queries — no cleanup needed.
                    "source_type": "tool_result",
                    "session_id": session_id,
                    "tool_name": tool_name,
                    "tool_input": tool_input[:500],
                    "blob_hash": blob_hash,
                    "timestamp": timestamp,
                }],
            )
            logger.debug("Stored tool result %s/%s", session_id, tool_name)
        except Exception as e:
            logger.error("Failed to store tool result %s/%s: %s", session_id, tool_name, e)

    def store_document_chunk(
        self,
        source_file: str,
        chunk_index: int,
        char_offset: int,
        blob_hash: str,
        text: str,
    ) -> None:
        """Embed and store a document chunk.

        Stores ``chunk_sha256`` (SHA-256 of the *full* chunk text) and
        ``stored_text_sha256`` (SHA-256 of the truncated 400-char preview
        actually persisted). The pair lets ``_verify_doc_chunk`` detect
        retrieval-time tampering of the stored excerpt without needing the
        original chunk text on hand.
        """
        if not text.strip():
            return
        try:
            import hashlib
            stored_excerpt = text[:400]
            full_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
            stored_sha = hashlib.sha256(stored_excerpt.encode("utf-8")).hexdigest()

            embedding = self._get_embedding(text)
            entry_id = f"doc_{blob_hash[:16]}_{chunk_index}"
            self._backend.upsert(
                ids=[entry_id],
                embeddings=[embedding],
                documents=[stored_excerpt],
                metadatas=[{
                    "source_type": "document",
                    "source_file": source_file,
                    "chunk_index": chunk_index,
                    "char_offset": char_offset,
                    "blob_hash": blob_hash,
                    "chunk_sha256": full_sha,
                    "stored_text_sha256": stored_sha,
                }],
            )
            logger.debug("Stored document chunk %s[%d]", source_file, chunk_index)
        except Exception as e:
            logger.error("Failed to store document chunk %s[%d]: %s", source_file, chunk_index, e)

    @staticmethod
    def _verify_doc_chunk(content: str, metadata: dict) -> bool:
        """Return False if the chunk's stored hash doesn't match its excerpt.

        Only enforced for entries with ``source_type=document`` AND a stored
        ``stored_text_sha256``. Older entries lack the field — passed through.
        On mismatch, emits a ``rag_quarantine`` wire event so an operator can
        triage. Caller decides whether to drop the result.
        """
        if metadata is None or metadata.get("source_type") != "document":
            return True
        expected = metadata.get("stored_text_sha256")
        if not expected:
            return True
        import hashlib
        actual = hashlib.sha256((content or "").encode("utf-8")).hexdigest()
        if actual == expected:
            return True
        logger.warning(
            "RAG chunk integrity mismatch: source=%s chunk_index=%s expected=%s... actual=%s...",
            metadata.get("source_file"), metadata.get("chunk_index"),
            expected[:8], actual[:8],
        )
        try:
            from beigebox.wiretap import log_event
            log_event(
                event_type="rag_quarantine",
                source="vector_store",
                content=f"chunk hash mismatch for {metadata.get('source_file')}[{metadata.get('chunk_index')}]",
                meta={
                    "source_file": metadata.get("source_file"),
                    "chunk_index": metadata.get("chunk_index"),
                    "expected_sha256": expected,
                    "actual_sha256": actual,
                },
            )
        except Exception:  # noqa: BLE001 — wire log emission must never block retrieval
            pass
        return False

    def get_stats(self) -> dict:
        """Return collection stats."""
        return {"total_embeddings": self._backend.count()}
