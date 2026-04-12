"""Tests for RAG Poisoning Detection router and integration layer."""

import math
import os
import tempfile

import numpy as np
import pytest
from fastapi.testclient import TestClient

from beigebox_security.api import create_app
from beigebox_security.integrations import poisoning as poisoning_mod
from beigebox_security.integrations.poisoning import (
    PoisoningService,
    RAGPoisoningDetector,
    reset_service,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PREFIX = "/v1/security/poisoning"


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Ensure each test gets a fresh service singleton."""
    reset_service()
    yield
    reset_service()


@pytest.fixture()
def tmp_db(tmp_path):
    """Provide a temporary SQLite DB path."""
    return str(tmp_path / "test_baselines.db")


@pytest.fixture()
def service(tmp_db):
    return PoisoningService(db_path=tmp_db)


@pytest.fixture()
def client(tmp_db, monkeypatch):
    """TestClient wired to a temp DB."""
    # Patch the module-level default so get_service() uses tmp_db
    monkeypatch.setattr(poisoning_mod, "_DB_PATH", tmp_db)
    app = create_app()
    return TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normal_embedding(dim: int = 128) -> list[float]:
    """Generate a realistic unit-norm embedding."""
    rng = np.random.default_rng(42)
    vec = rng.standard_normal(dim).astype(np.float32)
    vec = vec / np.linalg.norm(vec)  # unit norm
    return vec.tolist()


def _normal_batch(n: int = 20, dim: int = 128, seed: int = 0) -> list[list[float]]:
    rng = np.random.default_rng(seed)
    vecs = rng.standard_normal((n, dim)).astype(np.float32)
    norms = np.linalg.norm(vecs, axis=1, keepdims=True)
    vecs = vecs / norms
    return vecs.tolist()


def _poisoned_embedding_high_norm(dim: int = 128) -> list[float]:
    """Embedding with abnormally large magnitude."""
    return [500.0] * dim


def _poisoned_embedding_zero(dim: int = 128) -> list[float]:
    """Near-zero embedding."""
    return [0.0] * dim


# ===========================================================================
# Unit tests: RAGPoisoningDetector
# ===========================================================================


@pytest.mark.unit
class TestDetectorUnit:
    def test_empty_embedding_flagged(self):
        det = RAGPoisoningDetector()
        is_p, conf, reason = det.is_poisoned([])
        assert is_p is True
        assert conf == 1.0
        assert "Empty" in reason

    def test_zero_vector_flagged(self):
        det = RAGPoisoningDetector()
        is_p, conf, _reason = det.is_poisoned([0.0] * 128)
        assert is_p is True

    def test_huge_norm_flagged(self):
        det = RAGPoisoningDetector()
        is_p, conf, _reason = det.is_poisoned([999.0] * 128)
        assert is_p is True

    def test_normal_embedding_clean(self):
        det = RAGPoisoningDetector()
        is_p, conf, reason = det.is_poisoned(_normal_embedding())
        assert is_p is False
        assert conf == 0.0

    def test_baseline_update_and_z_score(self):
        det = RAGPoisoningDetector(sensitivity=0.95)
        # Build baseline of unit-norm vectors
        for emb in _normal_batch(50):
            det.update_baseline(emb)

        stats = det.get_baseline_stats()
        assert stats["count"] == 50
        assert 0.5 < stats["mean_norm"] < 2.0

        # Unit-norm vector should be clean
        is_p, _, _ = det.is_poisoned(_normal_embedding())
        assert is_p is False

        # Outlier (2x normal) should be flagged after baseline exists
        outlier = (np.array(_normal_embedding()) * 10).tolist()
        is_p, _, _ = det.is_poisoned(outlier)
        assert is_p is True

    def test_reset_baseline(self):
        det = RAGPoisoningDetector()
        det.update_baseline(_normal_embedding())
        assert det.get_baseline_stats()["count"] == 1
        det.reset_baseline()
        assert det.get_baseline_stats()["count"] == 0

    def test_export_import_baseline(self):
        det1 = RAGPoisoningDetector()
        for emb in _normal_batch(30):
            det1.update_baseline(emb)

        state = det1.export_baseline()
        det2 = RAGPoisoningDetector()
        det2.import_baseline(state)

        assert det2.get_baseline_stats()["count"] == det1.get_baseline_stats()["count"]
        assert det2.get_baseline_stats()["mean_norm"] == det1.get_baseline_stats()["mean_norm"]

    def test_valid_methods(self):
        assert "hybrid" in RAGPoisoningDetector.VALID_METHODS
        assert "magnitude" in RAGPoisoningDetector.VALID_METHODS
        assert len(RAGPoisoningDetector.VALID_METHODS) == 6


# ===========================================================================
# Integration tests: PoisoningService
# ===========================================================================


@pytest.mark.unit
class TestPoisoningService:
    def test_detect_empty_list(self, service):
        result = service.detect(embeddings=[], method="hybrid")
        assert result["poisoned"] == []
        assert result["scores"] == []
        assert result["confidence"] == 0.0

    def test_detect_clean_embeddings(self, service):
        embs = _normal_batch(5)
        result = service.detect(embeddings=embs, method="magnitude")
        assert len(result["poisoned"]) == 5
        assert all(p is False for p in result["poisoned"])

    def test_detect_poisoned_high_norm(self, service):
        embs = [_normal_embedding(), _poisoned_embedding_high_norm()]
        result = service.detect(embeddings=embs, method="hybrid")
        assert result["poisoned"][0] is False
        assert result["poisoned"][1] is True
        assert result["confidence"] > 0

    def test_detect_invalid_method(self, service):
        with pytest.raises(ValueError, match="Invalid method"):
            service.detect(embeddings=[_normal_embedding()], method="bogus")

    def test_scan_collection_empty(self, service):
        result = service.scan_collection("test_col", embeddings=[])
        assert result["total"] == 0
        assert result["flagged"] == 0

    def test_scan_collection_normal(self, service):
        embs = _normal_batch(30)
        result = service.scan_collection("test_col", embeddings=embs)
        assert result["collection_id"] == "test_col"
        assert result["total"] == 30
        # Normal batch should have few/no flags since baseline is built from them
        assert result["flagged"] <= 3  # allow tiny margin

    def test_scan_collection_with_outlier(self, service):
        embs = _normal_batch(30)
        embs.append(_poisoned_embedding_high_norm())
        result = service.scan_collection("test_col", embeddings=embs)
        assert result["total"] == 31
        assert 31 - 1 in result["flagged_indices"] or result["flagged"] >= 1

    def test_baseline_persistence(self, tmp_db):
        svc1 = PoisoningService(db_path=tmp_db)
        svc1.update_baseline("persist_col", _normal_batch(20))
        stats1 = svc1.get_baseline("persist_col")

        # New service instance loads from DB
        svc2 = PoisoningService(db_path=tmp_db)
        stats2 = svc2.get_baseline("persist_col")
        assert stats2 is not None
        assert stats2["count"] == stats1["count"]

    def test_get_baseline_not_found(self, service):
        assert service.get_baseline("nonexistent") is None

    def test_reset_baseline_service(self, service):
        service.update_baseline("reset_col", _normal_batch(10))
        assert service.get_baseline("reset_col") is not None
        service.reset_baseline("reset_col")
        # After reset, in-memory detector is cleared but entry still in dict
        stats = service.get_baseline("reset_col")
        assert stats["count"] == 0


# ===========================================================================
# Router / HTTP tests
# ===========================================================================


@pytest.mark.integration
class TestPoisoningRouter:
    def test_detect_valid_request(self, client):
        resp = client.post(
            f"{PREFIX}/detect",
            json={
                "embeddings": _normal_batch(3),
                "method": "hybrid",
                "sensitivity": 3.0,
                "collection_id": "test",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["poisoned"]) == 3
        assert len(body["scores"]) == 3
        assert body["method_used"] == "hybrid"
        assert "confidence" in body

    def test_detect_empty_embeddings(self, client):
        resp = client.post(
            f"{PREFIX}/detect",
            json={"embeddings": [], "method": "magnitude"},
        )
        assert resp.status_code == 200
        assert resp.json()["poisoned"] == []

    def test_detect_poisoned_embedding(self, client):
        resp = client.post(
            f"{PREFIX}/detect",
            json={
                "embeddings": [_poisoned_embedding_high_norm()],
                "method": "hybrid",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["poisoned"][0] is True

    def test_detect_zero_vector(self, client):
        resp = client.post(
            f"{PREFIX}/detect",
            json={"embeddings": [_poisoned_embedding_zero()]},
        )
        assert resp.status_code == 200
        assert resp.json()["poisoned"][0] is True

    def test_detect_invalid_method(self, client):
        resp = client.post(
            f"{PREFIX}/detect",
            json={"embeddings": [_normal_embedding()], "method": "bad_method"},
        )
        assert resp.status_code == 422

    def test_detect_single_embedding(self, client):
        resp = client.post(
            f"{PREFIX}/detect",
            json={"embeddings": [_normal_embedding()]},
        )
        assert resp.status_code == 200
        assert len(resp.json()["poisoned"]) == 1

    def test_detect_large_batch(self, client):
        batch = _normal_batch(100, seed=99)
        resp = client.post(
            f"{PREFIX}/detect",
            json={"embeddings": batch},
        )
        assert resp.status_code == 200
        assert len(resp.json()["poisoned"]) == 100

    def test_scan_endpoint(self, client):
        resp = client.post(
            f"{PREFIX}/scan",
            json={
                "collection_id": "scan_test",
                "embeddings": _normal_batch(20),
                "method": "hybrid",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["collection_id"] == "scan_test"
        assert body["total"] == 20

    def test_scan_with_outlier(self, client):
        embs = _normal_batch(20)
        embs.append(_poisoned_embedding_high_norm())
        resp = client.post(
            f"{PREFIX}/scan",
            json={"collection_id": "scan_outlier", "embeddings": embs},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["flagged"] >= 1

    def test_scan_empty(self, client):
        resp = client.post(
            f"{PREFIX}/scan",
            json={"collection_id": "empty_scan", "embeddings": []},
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_baseline_get_not_found(self, client):
        resp = client.get(f"{PREFIX}/baselines/nonexistent_collection")
        assert resp.status_code == 404

    def test_baseline_update_and_get(self, client):
        embs = _normal_batch(15)
        resp = client.post(
            f"{PREFIX}/baselines/my_col",
            json={"embeddings": embs},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["collection_id"] == "my_col"
        assert body["count"] == 15

        # GET should return the baseline
        resp2 = client.get(f"{PREFIX}/baselines/my_col")
        assert resp2.status_code == 200
        assert resp2.json()["count"] == 15

    def test_baseline_update_empty(self, client):
        resp = client.post(
            f"{PREFIX}/baselines/my_col",
            json={"embeddings": []},
        )
        assert resp.status_code == 422

    def test_baseline_delete(self, client):
        # Create
        client.post(
            f"{PREFIX}/baselines/del_col",
            json={"embeddings": _normal_batch(5)},
        )
        # Delete
        resp = client.delete(f"{PREFIX}/baselines/del_col")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_detect_all_methods(self, client):
        """Ensure every valid method is accepted."""
        for method in RAGPoisoningDetector.VALID_METHODS:
            resp = client.post(
                f"{PREFIX}/detect",
                json={"embeddings": [_normal_embedding()], "method": method},
            )
            assert resp.status_code == 200, f"Method {method} failed"
            assert resp.json()["method_used"] == method

    def test_detect_mixed_clean_and_poisoned(self, client):
        """Batch with both clean and poisoned vectors."""
        embs = _normal_batch(5)
        embs.append(_poisoned_embedding_high_norm())
        embs.append(_poisoned_embedding_zero())
        resp = client.post(
            f"{PREFIX}/detect",
            json={"embeddings": embs},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["poisoned"]) == 7
        # Last two should be flagged
        assert body["poisoned"][-1] is True
        assert body["poisoned"][-2] is True
        # First 5 should be clean
        assert all(p is False for p in body["poisoned"][:5])

    def test_detect_false_positive_rate(self, client):
        """Legitimate embeddings should not be flagged."""
        batch = _normal_batch(50, seed=777)
        resp = client.post(
            f"{PREFIX}/detect",
            json={"embeddings": batch, "sensitivity": 3.0},
        )
        assert resp.status_code == 200
        flagged = sum(resp.json()["poisoned"])
        # Allow at most 5% false positives
        assert flagged / 50 < 0.05, f"Too many false positives: {flagged}/50"
