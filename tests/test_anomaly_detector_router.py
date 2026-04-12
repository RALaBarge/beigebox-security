"""Tests for API Anomaly Detection router and integration layer.

Covers:
  - Normal traffic patterns (no false positives)
  - Request rate spike detection
  - Error rate spike detection
  - Model switching anomalies
  - Payload size outliers
  - Cold start / warming_up vs established baselines
  - False positive handling on legitimate traffic
  - Risk score calculation
  - Report generation
  - Baseline retrieval and reset
  - Sensitivity level switching
"""

import time

import pytest
from fastapi.testclient import TestClient

from beigebox_security.api import create_app
from beigebox_security.integrations.anomaly import (
    AnomalyDetectorService,
    compute_risk_score,
    recommended_action,
    reset_detector,
    get_detector,
    SENSITIVITY_PRESETS,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Reset the global detector singleton between tests."""
    reset_detector()
    yield
    reset_detector()


@pytest.fixture
def detector() -> AnomalyDetectorService:
    """Fresh in-memory detector with medium sensitivity and low baseline requirement."""
    return AnomalyDetectorService(sensitivity="medium", db_path="", window_seconds=300)


@pytest.fixture
def warmed_detector() -> AnomalyDetectorService:
    """Detector with an established baseline (50+ normal requests)."""
    d = AnomalyDetectorService(sensitivity="medium", db_path="", window_seconds=300)
    # Ingest 60 normal requests to establish baseline
    for i in range(60):
        d.ingest("session-warm", model="gpt-4", request_bytes=500, status_code=200)
    return d


@pytest.fixture
def client() -> TestClient:
    """TestClient wired to the app."""
    app = create_app()
    return TestClient(app)


def _ingest_normal(detector: AnomalyDetectorService, session_id: str, count: int = 60):
    """Helper: ingest normal traffic to establish baseline."""
    for _ in range(count):
        detector.ingest(session_id, model="gpt-4", request_bytes=500, status_code=200)


# ── Unit: risk score & action ─────────────────────────────────────────────────


@pytest.mark.unit
class TestRiskScore:
    def test_no_rules_zero_score(self):
        assert compute_risk_score([]) == 0.0

    def test_single_rule_weight(self):
        score = compute_risk_score(["request_rate_spike"])
        assert score == 0.3

    def test_multiple_rules_compound(self):
        score = compute_risk_score(["request_rate_spike", "error_rate_spike"])
        assert score == 0.55

    def test_all_four_signals(self):
        score = compute_risk_score([
            "request_rate_spike", "error_rate_spike",
            "model_switching", "payload_size_anomaly",
        ])
        assert score == 0.85

    def test_score_capped_at_one(self):
        # Throw in extra rules to exceed 1.0
        score = compute_risk_score([
            "request_rate_spike", "error_rate_spike",
            "model_switching", "payload_size_anomaly",
            "unknown_rule_1", "unknown_rule_2", "unknown_rule_3", "unknown_rule_4",
        ])
        assert score == 1.0

    def test_recommended_action_allow(self):
        assert recommended_action(0.0) == "allow"
        assert recommended_action(0.29) == "allow"

    def test_recommended_action_warn(self):
        assert recommended_action(0.3) == "warn"
        assert recommended_action(0.69) == "warn"

    def test_recommended_action_rate_limit(self):
        assert recommended_action(0.7) == "rate_limit"
        assert recommended_action(1.0) == "rate_limit"


# ── Unit: detection signals ───────────────────────────────────────────────────


@pytest.mark.unit
class TestNormalTraffic:
    """Normal traffic should produce no anomalies (false positive check)."""

    def test_normal_traffic_no_anomalies(self, warmed_detector):
        # One more normal request after baseline
        warmed_detector.ingest("session-warm", model="gpt-4", request_bytes=500, status_code=200)
        result = warmed_detector.analyze("session-warm")
        assert result["risk_score"] == 0.0
        assert result["anomalies"] == []
        assert result["recommended_action"] == "allow"

    def test_normal_traffic_various_models_under_threshold(self, detector):
        """Using a few different models is fine as long as under threshold."""
        _ingest_normal(detector, "session-models", count=60)
        # Add 3 different models within window — well under threshold of 8
        for m in ["gpt-4", "gpt-3.5", "claude-3"]:
            detector.ingest("session-models", model=m, request_bytes=500, status_code=200)
        result = detector.analyze("session-models")
        assert result["risk_score"] == 0.0

    def test_legitimate_high_volume_no_false_positive(self, detector):
        """Steady high traffic that builds into baseline should not trigger."""
        # Build baseline at steady rate
        for _ in range(80):
            detector.ingest("session-steady", model="gpt-4", request_bytes=500, status_code=200)
        result = detector.analyze("session-steady")
        # Should be clean — the rate is consistent
        assert result["recommended_action"] == "allow"


@pytest.mark.unit
class TestRequestRateSpike:
    """Signal 1: Request rate spike detection."""

    def test_cold_start_rate_spike(self, detector):
        """Before baseline is established, use simple threshold."""
        # Ingest 10 requests (under min_baseline_size=50) to create session
        for _ in range(10):
            detector.ingest("session-rate", model="gpt-4", request_bytes=500, status_code=200)
        result = detector.analyze("session-rate")
        # 10 requests in the last minute with threshold of 5 → spike
        assert "request_rate_spike" in [a["type"] for a in result["anomalies"]]
        assert result["baseline_status"] == "warming_up"

    def test_established_baseline_rate_spike(self):
        """After baseline with low rate samples, a burst triggers z-score detection."""
        d = AnomalyDetectorService(sensitivity="medium", db_path="", window_seconds=300)

        # Build baseline: manually set low rate samples to simulate slow traffic
        d.ingest("session-zrate", model="gpt-4", request_bytes=500, status_code=200)
        session = d._sessions["session-zrate"]
        session.request_count = 60  # Mark as established
        # Simulate historical rate samples of ~1 request/min with low variance
        session.rate_samples.clear()
        for _ in range(100):
            session.rate_samples.append(1)

        # Now burst: inject many requests so current minute count is high
        for _ in range(40):
            d.ingest("session-zrate", model="gpt-4", request_bytes=500, status_code=200)

        result = d.analyze("session-zrate")
        types = [a["type"] for a in result["anomalies"]]
        assert "request_rate_spike" in types


@pytest.mark.unit
class TestErrorRateSpike:
    """Signal 2: Error rate spike detection."""

    def test_cold_start_error_spike(self, detector):
        """High error rate before baseline triggers simple threshold."""
        # 3 successful, then 7 errors → 70% error rate
        for _ in range(3):
            detector.ingest("session-err", model="gpt-4", request_bytes=500, status_code=200)
        for _ in range(7):
            detector.ingest("session-err", model="gpt-4", request_bytes=500, status_code=500)
        result = detector.analyze("session-err")
        types = [a["type"] for a in result["anomalies"]]
        assert "error_rate_spike" in types

    def test_established_baseline_error_spike(self):
        """After baseline with low error rate, sudden errors trigger z-score.

        We directly set up internal state to simulate time-separated traffic,
        then verify the detection logic sees the spike.
        """
        d = AnomalyDetectorService(sensitivity="medium", db_path="", window_seconds=300)
        from beigebox_security.integrations.anomaly import SessionBaseline, RequestRecord
        import time

        now = time.time()
        session = SessionBaseline(session_id="session-zerr")
        session.request_count = 60

        # Simulate 60 successful requests spread over the window
        for i in range(60):
            session.request_history.append(
                RequestRecord(timestamp=now - 200 + i, model="gpt-4", request_bytes=500, status_code=200)
            )
        session.error_rate_samples.clear()
        for _ in range(60):
            session.error_rate_samples.append(0.0)

        # Now add 20 errors at current time
        for i in range(20):
            session.request_history.append(
                RequestRecord(timestamp=now, model="gpt-4", request_bytes=500, status_code=500)
            )
            session.error_count += 1
            session.request_count += 1

        d._sessions["session-zerr"] = session

        result = d.analyze("session-zerr")
        types = [a["type"] for a in result["anomalies"]]
        assert "error_rate_spike" in types


@pytest.mark.unit
class TestModelSwitching:
    """Signal 3: Model switching anomaly."""

    def test_excessive_model_switching(self, detector):
        """More models than threshold in window should trigger."""
        _ingest_normal(detector, "session-switch", count=10)
        # Switch through 10 distinct models (threshold is 8 for medium)
        for i in range(10):
            detector.ingest("session-switch", model=f"model-{i}", request_bytes=500, status_code=200)
        result = detector.analyze("session-switch")
        types = [a["type"] for a in result["anomalies"]]
        assert "model_switching" in types

    def test_model_switching_under_threshold(self, detector):
        """Using few models should not trigger."""
        _ingest_normal(detector, "session-few-models", count=60)
        for m in ["gpt-4", "gpt-3.5"]:
            detector.ingest("session-few-models", model=m, request_bytes=500, status_code=200)
        result = detector.analyze("session-few-models")
        types = [a["type"] for a in result["anomalies"]]
        assert "model_switching" not in types


@pytest.mark.unit
class TestPayloadSize:
    """Signal 4: Payload size outliers."""

    def test_tiny_payload_triggers(self, detector):
        """Payload below min_chars should trigger."""
        _ingest_normal(detector, "session-tiny", count=5)
        detector.ingest("session-tiny", model="gpt-4", request_bytes=10, status_code=200)
        result = detector.analyze("session-tiny")
        types = [a["type"] for a in result["anomalies"]]
        assert "payload_size_anomaly" in types

    def test_huge_payload_triggers(self, detector):
        """Payload above max_bytes should trigger."""
        _ingest_normal(detector, "session-huge", count=5)
        detector.ingest("session-huge", model="gpt-4", request_bytes=200_000, status_code=200)
        result = detector.analyze("session-huge")
        types = [a["type"] for a in result["anomalies"]]
        assert "payload_size_anomaly" in types

    def test_normal_payload_no_trigger(self, detector):
        """Normal payload sizes should not trigger."""
        _ingest_normal(detector, "session-normal-payload", count=60)
        detector.ingest("session-normal-payload", model="gpt-4", request_bytes=500, status_code=200)
        result = detector.analyze("session-normal-payload")
        types = [a["type"] for a in result["anomalies"]]
        assert "payload_size_anomaly" not in types


# ── Unit: baseline status ─────────────────────────────────────────────────────


@pytest.mark.unit
class TestBaselineStatus:
    def test_insufficient_data(self, detector):
        """No data at all → insufficient_data."""
        result = detector.analyze("nonexistent-session")
        assert result["baseline_status"] == "insufficient_data"

    def test_warming_up(self, detector):
        """Some data but under min_baseline_size → warming_up."""
        for _ in range(5):
            detector.ingest("session-warming", model="gpt-4", request_bytes=500, status_code=200)
        result = detector.analyze("session-warming")
        assert result["baseline_status"] == "warming_up"

    def test_established(self, warmed_detector):
        """Enough data → established."""
        result = warmed_detector.analyze("session-warm")
        assert result["baseline_status"] == "established"


# ── Unit: sensitivity switching ───────────────────────────────────────────────


@pytest.mark.unit
class TestSensitivity:
    def test_high_sensitivity_catches_more(self):
        """High sensitivity (lower thresholds) should catch borderline anomalies."""
        d = AnomalyDetectorService(sensitivity="high", db_path="", window_seconds=300)
        # 5 requests → over the high threshold of 3
        for _ in range(5):
            d.ingest("session-high", model="gpt-4", request_bytes=500, status_code=200)
        result = d.analyze("session-high")
        types = [a["type"] for a in result["anomalies"]]
        assert "request_rate_spike" in types

    def test_low_sensitivity_misses_borderline(self):
        """Low sensitivity (higher thresholds) should not trigger on moderate traffic."""
        d = AnomalyDetectorService(sensitivity="low", db_path="", window_seconds=300)
        # 8 requests → under the low threshold of 10
        for _ in range(8):
            d.ingest("session-low", model="gpt-4", request_bytes=500, status_code=200)
        result = d.analyze("session-low")
        assert result["risk_score"] == 0.0


# ── Integration: router endpoints ─────────────────────────────────────────────


@pytest.mark.integration
class TestAnalyzeEndpoint:
    def test_analyze_empty_session(self, client):
        """Analyzing unknown session returns clean result."""
        resp = client.post(
            "/v1/security/anomaly/analyze",
            json={"session_id": "unknown-session"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == "unknown-session"
        assert data["risk_score"] == 0.0
        assert data["recommended_action"] == "allow"
        assert data["baseline_status"] == "insufficient_data"

    def test_analyze_with_traffic(self, client):
        """Analyze after ingesting traffic returns proper structure."""
        detector = get_detector()
        _ingest_normal(detector, "api-session", count=10)

        resp = client.post(
            "/v1/security/anomaly/analyze",
            json={"session_id": "api-session", "sensitivity": "medium"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == "api-session"
        assert "risk_score" in data
        assert "anomalies" in data
        assert "recommended_action" in data
        assert "baseline_status" in data

    def test_analyze_invalid_sensitivity(self, client):
        """Invalid sensitivity should be rejected by validation."""
        resp = client.post(
            "/v1/security/anomaly/analyze",
            json={"session_id": "test", "sensitivity": "ultra"},
        )
        assert resp.status_code == 422


@pytest.mark.integration
class TestReportEndpoint:
    def test_report_unknown_session_404(self, client):
        """Report for unknown session returns 404."""
        resp = client.get("/v1/security/anomaly/report/nonexistent")
        assert resp.status_code == 404

    def test_report_with_data(self, client):
        """Report for session with data returns full structure."""
        detector = get_detector()
        _ingest_normal(detector, "report-session", count=20)

        resp = client.get("/v1/security/anomaly/report/report-session")
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == "report-session"
        assert "baselines" in data
        assert "analysis" in data
        assert "summary" in data
        assert data["summary"]["total_requests"] == 20

    def test_report_format_param(self, client):
        """Format parameter is accepted (json default)."""
        detector = get_detector()
        _ingest_normal(detector, "format-session", count=5)
        resp = client.get("/v1/security/anomaly/report/format-session?format=json")
        assert resp.status_code == 200


@pytest.mark.integration
class TestBaselinesEndpoint:
    def test_baselines_unknown_session_404(self, client):
        """Baselines for unknown session returns 404."""
        resp = client.get("/v1/security/anomaly/baselines/nonexistent")
        assert resp.status_code == 404

    def test_baselines_with_data(self, client):
        """Baselines for session with data returns metrics."""
        detector = get_detector()
        _ingest_normal(detector, "baseline-session", count=60)

        resp = client.get("/v1/security/anomaly/baselines/baseline-session")
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == "baseline-session"
        assert data["request_count"] == 60
        assert data["baseline_status"] == "established"
        assert data["mean_rate"] > 0
        assert "gpt-4" in data["distinct_models"]


@pytest.mark.integration
class TestResetEndpoint:
    def test_reset_baseline(self, client):
        """Reset clears session data."""
        detector = get_detector()
        _ingest_normal(detector, "reset-session", count=30)

        # Verify data exists
        resp = client.get("/v1/security/anomaly/baselines/reset-session")
        assert resp.status_code == 200

        # Reset
        resp = client.post("/v1/security/anomaly/reset-baseline/reset-session")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "reset"
        assert data["session_id"] == "reset-session"

        # Verify data is gone
        resp = client.get("/v1/security/anomaly/baselines/reset-session")
        assert resp.status_code == 404

    def test_reset_nonexistent_session(self, client):
        """Resetting nonexistent session succeeds (idempotent)."""
        resp = client.post("/v1/security/anomaly/reset-baseline/ghost-session")
        assert resp.status_code == 200


# ── Integration: false positive rate ──────────────────────────────────────────


@pytest.mark.integration
class TestFalsePositiveRate:
    def test_false_positive_rate_under_ten_percent(self):
        """Run 100 normal sessions and verify <10% false positives."""
        d = AnomalyDetectorService(sensitivity="medium", db_path="", window_seconds=300)
        false_positives = 0

        for i in range(100):
            sid = f"fp-session-{i}"
            # Each session: 3-5 normal requests (well under threshold)
            for _ in range(3):
                d.ingest(sid, model="gpt-4", request_bytes=500, status_code=200)
            result = d.analyze(sid)
            if result["risk_score"] > 0:
                false_positives += 1

        fp_rate = false_positives / 100
        assert fp_rate < 0.10, f"False positive rate {fp_rate*100:.0f}% exceeds 10% threshold"


# ── Unit: SQLite baseline persistence ─────────────────────────────────────────


@pytest.mark.unit
class TestBaselinePersistence:
    def test_persist_and_reload(self, tmp_path):
        """Baselines survive detector recreation via SQLite."""
        db = str(tmp_path / "test_baselines.db")

        d1 = AnomalyDetectorService(sensitivity="medium", db_path=db)
        _ingest_normal(d1, "persist-session", count=60)
        d1.persist_session("persist-session")

        # Create new detector pointing at same DB
        d2 = AnomalyDetectorService(sensitivity="medium", db_path=db)
        baselines = d2.get_baselines("persist-session")
        assert baselines["request_count"] == 60
        assert baselines["source"] == "persisted"
        assert baselines["baseline_status"] == "established"
