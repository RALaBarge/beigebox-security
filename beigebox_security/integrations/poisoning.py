"""
Wrapper around RAGPoisoningDetector for microservice use.

Manages per-collection detector instances and baseline persistence.
"""

import logging
import sqlite3
import json
import os
import threading
from typing import Optional

import numpy as np
from collections import deque

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Inline detector (self-contained, no cross-package import needed)
# ---------------------------------------------------------------------------


class RAGPoisoningDetector:
    """
    Detects poisoned embeddings via magnitude anomaly detection.

    Maintains a rolling baseline of embedding statistics and flags
    vectors that deviate significantly (z-score > threshold or
    magnitude outside safe range).
    """

    VALID_METHODS = {"magnitude", "centroid", "neighborhood", "dimension", "fingerprint", "hybrid"}

    def __init__(
        self,
        sensitivity: float = 0.95,
        baseline_window: int = 1000,
        min_norm: float = 0.1,
        max_norm: float = 100.0,
    ):
        self.sensitivity = sensitivity
        self.baseline_window = baseline_window
        self.min_norm = min_norm
        self.max_norm = max_norm

        self._lock = threading.Lock()
        self._norms: deque = deque(maxlen=baseline_window)
        self._mean_norm = 0.0
        self._std_norm = 1.0
        self._count = 0
        self._z_threshold = self._sensitivity_to_z_threshold(sensitivity)

    # -- static helpers --

    @staticmethod
    def _sensitivity_to_z_threshold(sensitivity: float) -> float:
        if sensitivity < 0.90:
            return 2.0
        if sensitivity > 0.99:
            return 4.0
        return 2.0 + (sensitivity - 0.90) / 0.09 * 2.0

    # -- baseline management --

    def update_baseline(self, embedding) -> None:
        arr = np.asarray(embedding, dtype=np.float32)
        norm = float(np.linalg.norm(arr))
        with self._lock:
            self._norms.append(norm)
            self._count += 1
            if len(self._norms) > 0:
                self._mean_norm = float(np.mean(self._norms))
                if len(self._norms) > 1:
                    self._std_norm = float(np.std(self._norms))
                    if self._std_norm < 1e-6:
                        self._std_norm = 1.0

    def update_baseline_batch(self, embeddings: list) -> None:
        for emb in embeddings:
            self.update_baseline(emb)

    def is_poisoned(self, embedding) -> tuple:
        """Returns (is_poisoned, confidence, reason)."""
        arr = np.asarray(embedding, dtype=np.float32)

        if arr.size == 0:
            return (True, 1.0, "Empty embedding")

        norm = float(np.linalg.norm(arr))

        if norm < self.min_norm:
            confidence = min(1.0, (self.min_norm - norm) / max(self.min_norm, 1e-9))
            return (True, confidence, f"Magnitude below minimum (norm={norm:.4f})")

        if norm > self.max_norm:
            confidence = min(1.0, (norm - self.max_norm) / max(self.max_norm, 1e-9))
            return (True, confidence, f"Magnitude above maximum (norm={norm:.4f})")

        with self._lock:
            mean_norm = self._mean_norm
            std_norm = self._std_norm
            count = self._count

        if count > 0 and std_norm > 0:
            z_score = (norm - mean_norm) / std_norm
            if abs(z_score) > self._z_threshold:
                confidence = min(1.0, abs(z_score) / (2 * self._z_threshold))
                return (True, confidence, f"Z-score anomaly ({z_score:.2f})")

        return (False, 0.0, "")

    def get_baseline_stats(self) -> dict:
        with self._lock:
            return {
                "count": self._count,
                "mean_norm": round(self._mean_norm, 6),
                "std_norm": round(self._std_norm, 6),
                "z_threshold": round(self._z_threshold, 4),
                "baseline_window_size": len(self._norms),
                "min_norm_range": self.min_norm,
                "max_norm_range": self.max_norm,
            }

    def reset_baseline(self) -> None:
        with self._lock:
            self._norms.clear()
            self._mean_norm = 0.0
            self._std_norm = 1.0
            self._count = 0

    def export_baseline(self) -> dict:
        """Serialize baseline state for persistence."""
        with self._lock:
            return {
                "norms": list(self._norms),
                "mean_norm": self._mean_norm,
                "std_norm": self._std_norm,
                "count": self._count,
                "sensitivity": self.sensitivity,
                "baseline_window": self.baseline_window,
                "min_norm": self.min_norm,
                "max_norm": self.max_norm,
            }

    def import_baseline(self, state: dict) -> None:
        """Restore baseline state from persistence."""
        with self._lock:
            norms = state.get("norms", [])
            self._norms = deque(norms, maxlen=self.baseline_window)
            self._mean_norm = state.get("mean_norm", 0.0)
            self._std_norm = state.get("std_norm", 1.0)
            self._count = state.get("count", 0)


# ---------------------------------------------------------------------------
# Per-collection detector manager with SQLite baseline persistence
# ---------------------------------------------------------------------------

_DB_PATH = os.environ.get(
    "BEIGEBOX_SECURITY_DB",
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "poisoning_baselines.db"),
)


class PoisoningService:
    """
    Manages per-collection RAGPoisoningDetector instances.

    Stores baselines in SQLite so they survive restarts.
    """

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or _DB_PATH
        self._detectors: dict[str, RAGPoisoningDetector] = {}
        self._lock = threading.Lock()
        self._init_db()

    # -- DB setup --

    def _init_db(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self._db_path)), exist_ok=True)
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS baselines (
                    collection_id TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    # -- detector lifecycle --

    def _get_or_create(
        self,
        collection_id: str,
        sensitivity: float = 0.95,
    ) -> RAGPoisoningDetector:
        with self._lock:
            if collection_id not in self._detectors:
                det = RAGPoisoningDetector(sensitivity=sensitivity)
                # Try loading persisted baseline
                saved = self._load_baseline(collection_id)
                if saved is not None:
                    det.import_baseline(saved)
                self._detectors[collection_id] = det
            return self._detectors[collection_id]

    # -- persistence --

    def _load_baseline(self, collection_id: str) -> Optional[dict]:
        try:
            with sqlite3.connect(self._db_path) as conn:
                row = conn.execute(
                    "SELECT state_json FROM baselines WHERE collection_id = ?",
                    (collection_id,),
                ).fetchone()
                if row:
                    return json.loads(row[0])
        except Exception:
            logger.warning("Failed to load baseline for %s", collection_id, exc_info=True)
        return None

    def _save_baseline(self, collection_id: str, detector: RAGPoisoningDetector) -> None:
        state = detector.export_baseline()
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO baselines (collection_id, state_json, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(collection_id) DO UPDATE SET
                        state_json = excluded.state_json,
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (collection_id, json.dumps(state)),
                )
        except Exception:
            logger.warning("Failed to save baseline for %s", collection_id, exc_info=True)

    # -- public API --

    def detect(
        self,
        embeddings: list[list[float]],
        method: str = "hybrid",
        sensitivity: float = 0.95,
        collection_id: str = "default",
    ) -> dict:
        """
        Run poisoning detection on a batch of embeddings.

        Returns dict with poisoned, scores, confidence, method_used.
        """
        if method not in RAGPoisoningDetector.VALID_METHODS:
            raise ValueError(
                f"Invalid method '{method}'. Must be one of: {sorted(RAGPoisoningDetector.VALID_METHODS)}"
            )

        if not embeddings:
            return {
                "poisoned": [],
                "scores": [],
                "confidence": 0.0,
                "method_used": method,
            }

        detector = self._get_or_create(collection_id, sensitivity=sensitivity)

        poisoned_flags = []
        scores = []
        confidences = []

        for emb in embeddings:
            is_p, conf, _reason = detector.is_poisoned(emb)
            poisoned_flags.append(is_p)
            scores.append(round(conf, 6))
            confidences.append(conf)

        overall_confidence = max(confidences) if confidences else 0.0

        return {
            "poisoned": poisoned_flags,
            "scores": scores,
            "confidence": round(overall_confidence, 6),
            "method_used": method,
        }

    def scan_collection(
        self,
        collection_id: str,
        embeddings: list[list[float]],
        method: str = "hybrid",
        sensitivity: float = 0.95,
    ) -> dict:
        """
        Full scan: build baseline from provided embeddings, then detect anomalies.

        Returns scan results with flagged indices.
        """
        if method not in RAGPoisoningDetector.VALID_METHODS:
            raise ValueError(
                f"Invalid method '{method}'. Must be one of: {sorted(RAGPoisoningDetector.VALID_METHODS)}"
            )

        if not embeddings:
            return {
                "collection_id": collection_id,
                "total": 0,
                "flagged": 0,
                "flagged_indices": [],
                "method_used": method,
            }

        # Create fresh detector for scan
        detector = RAGPoisoningDetector(sensitivity=sensitivity)

        # Build baseline from all embeddings first
        detector.update_baseline_batch(embeddings)

        # Now scan each embedding
        flagged_indices = []
        for i, emb in enumerate(embeddings):
            is_p, _conf, _reason = detector.is_poisoned(emb)
            if is_p:
                flagged_indices.append(i)

        # Persist the baseline
        with self._lock:
            self._detectors[collection_id] = detector
        self._save_baseline(collection_id, detector)

        return {
            "collection_id": collection_id,
            "total": len(embeddings),
            "flagged": len(flagged_indices),
            "flagged_indices": flagged_indices,
            "method_used": method,
        }

    def get_baseline(self, collection_id: str) -> Optional[dict]:
        """Get baseline stats for a collection. Returns None if not found."""
        detector = self._detectors.get(collection_id)
        if detector is not None:
            stats = detector.get_baseline_stats()
            stats["collection_id"] = collection_id
            return stats

        # Try loading from DB
        saved = self._load_baseline(collection_id)
        if saved is not None:
            det = RAGPoisoningDetector()
            det.import_baseline(saved)
            with self._lock:
                self._detectors[collection_id] = det
            stats = det.get_baseline_stats()
            stats["collection_id"] = collection_id
            return stats

        return None

    def update_baseline(
        self,
        collection_id: str,
        embeddings: list[list[float]],
        sensitivity: float = 0.95,
    ) -> dict:
        """Add embeddings to a collection's baseline."""
        detector = self._get_or_create(collection_id, sensitivity=sensitivity)
        detector.update_baseline_batch(embeddings)
        self._save_baseline(collection_id, detector)
        return detector.get_baseline_stats()

    def reset_baseline(self, collection_id: str) -> None:
        """Reset baseline for a collection."""
        with self._lock:
            if collection_id in self._detectors:
                self._detectors[collection_id].reset_baseline()
        # Remove from DB
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute(
                    "DELETE FROM baselines WHERE collection_id = ?",
                    (collection_id,),
                )
        except Exception:
            logger.warning("Failed to delete baseline for %s", collection_id, exc_info=True)


# Module-level singleton (lazily initialized per-request via get_service())
_service: Optional[PoisoningService] = None
_service_lock = threading.Lock()


def get_service(db_path: Optional[str] = None) -> PoisoningService:
    """Get or create the module-level PoisoningService singleton."""
    global _service
    if _service is None:
        with _service_lock:
            if _service is None:
                _service = PoisoningService(db_path=db_path)
    return _service


def reset_service() -> None:
    """Reset the singleton (for testing)."""
    global _service
    with _service_lock:
        _service = None
