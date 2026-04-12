"""Anomaly detection integration layer.

Wraps the z-score based APIAnomalyDetector with session-oriented API
suitable for the beigebox-security microservice endpoints.
"""

import json
import logging
import sqlite3
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# ── Sensitivity presets ─────────────────────────────────────────────────────

SENSITIVITY_PRESETS = {
    "low": {
        "z_threshold": 4.0,
        "request_rate_threshold": 10,
        "error_rate_threshold": 0.40,
        "model_switch_threshold": 12,
        "payload_min_chars": 20,
        "payload_max_bytes": 200_000,
        "min_baseline_size": 80,
    },
    "medium": {
        "z_threshold": 3.0,
        "request_rate_threshold": 5,
        "error_rate_threshold": 0.30,
        "model_switch_threshold": 8,
        "payload_min_chars": 50,
        "payload_max_bytes": 100_000,
        "min_baseline_size": 50,
    },
    "high": {
        "z_threshold": 2.0,
        "request_rate_threshold": 3,
        "error_rate_threshold": 0.15,
        "model_switch_threshold": 4,
        "payload_min_chars": 80,
        "payload_max_bytes": 50_000,
        "min_baseline_size": 30,
    },
}

# ── Rule severity weights ────────────────────────────────────────────────────

_RULE_WEIGHTS = {
    "request_rate_spike": 0.30,
    "error_rate_spike": 0.25,
    "model_switching": 0.20,
    "payload_size_anomaly": 0.10,
}


def compute_risk_score(triggered_rules: list[str]) -> float:
    """Compute composite risk score from triggered rules (0.0-1.0)."""
    if not triggered_rules:
        return 0.0
    score = sum(_RULE_WEIGHTS.get(r, 0.05) for r in triggered_rules)
    return round(min(1.0, score), 3)


def recommended_action(risk_score: float) -> str:
    """Map risk score to recommended action."""
    if risk_score >= 0.7:
        return "rate_limit"
    if risk_score >= 0.3:
        return "warn"
    return "allow"


# ── Request / session data ────────────────────────────────────────────────────


@dataclass
class RequestRecord:
    """Single API request record."""
    timestamp: float
    model: str
    request_bytes: int
    status_code: int


@dataclass
class SessionBaseline:
    """Per-session statistics and rolling baselines."""
    session_id: str
    request_count: int = 0
    error_count: int = 0
    distinct_models: set = field(default_factory=set)
    request_history: deque = field(default_factory=lambda: deque(maxlen=500))
    rate_samples: deque = field(default_factory=lambda: deque(maxlen=200))
    error_rate_samples: deque = field(default_factory=lambda: deque(maxlen=200))
    payload_sizes: deque = field(default_factory=lambda: deque(maxlen=500))
    last_seen: float = 0.0


# ── SQLite baseline storage ──────────────────────────────────────────────────

_BASELINES_SCHEMA = """
CREATE TABLE IF NOT EXISTS session_baselines (
    session_id        TEXT PRIMARY KEY,
    request_count     INTEGER DEFAULT 0,
    error_count       INTEGER DEFAULT 0,
    mean_rate         REAL DEFAULT 0.0,
    std_rate          REAL DEFAULT 1.0,
    mean_error_rate   REAL DEFAULT 0.0,
    std_error_rate    REAL DEFAULT 0.1,
    mean_payload_size REAL DEFAULT 0.0,
    std_payload_size  REAL DEFAULT 1.0,
    distinct_models   TEXT DEFAULT '[]',
    last_seen         REAL DEFAULT 0.0,
    updated_at        TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS anomaly_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    session_id  TEXT NOT NULL,
    rules       TEXT NOT NULL,
    risk_score  REAL NOT NULL,
    action      TEXT NOT NULL,
    meta        TEXT
);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_session ON anomaly_events(session_id);
"""


class BaselineStore:
    """SQLite-backed baseline persistence."""

    def __init__(self, db_path: str = ""):
        self._conn: Optional[sqlite3.Connection] = None
        if db_path:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            try:
                self._conn = sqlite3.connect(db_path, check_same_thread=False)
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.executescript(_BASELINES_SCHEMA)
                self._conn.commit()
            except Exception as e:
                logger.warning("BaselineStore init failed (%s): %s", db_path, e)
                self._conn = None

    def save(self, session_id: str, baseline: "SessionBaseline") -> None:
        if not self._conn:
            return
        try:
            rates = list(baseline.rate_samples)
            errors = list(baseline.error_rate_samples)
            payloads = list(baseline.payload_sizes)

            mean_rate = float(np.mean(rates)) if rates else 0.0
            std_rate = float(np.std(rates)) if len(rates) > 1 else 1.0
            mean_err = float(np.mean(errors)) if errors else 0.0
            std_err = float(np.std(errors)) if len(errors) > 1 else 0.1
            mean_payload = float(np.mean(payloads)) if payloads else 0.0
            std_payload = float(np.std(payloads)) if len(payloads) > 1 else 1.0

            self._conn.execute(
                """INSERT OR REPLACE INTO session_baselines
                   (session_id, request_count, error_count,
                    mean_rate, std_rate, mean_error_rate, std_error_rate,
                    mean_payload_size, std_payload_size, distinct_models, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session_id, baseline.request_count, baseline.error_count,
                    mean_rate, std_rate, mean_err, std_err,
                    mean_payload, std_payload,
                    json.dumps(sorted(baseline.distinct_models)),
                    baseline.last_seen,
                ),
            )
            self._conn.commit()
        except Exception as e:
            logger.debug("save(%s) failed: %s", session_id, e)

    def load(self, session_id: str) -> Optional[dict]:
        if not self._conn:
            return None
        try:
            row = self._conn.execute(
                "SELECT * FROM session_baselines WHERE session_id = ?", (session_id,)
            ).fetchone()
            if not row:
                return None
            cols = [
                "session_id", "request_count", "error_count",
                "mean_rate", "std_rate", "mean_error_rate", "std_error_rate",
                "mean_payload_size", "std_payload_size",
                "distinct_models", "last_seen", "updated_at",
            ]
            return dict(zip(cols, row))
        except Exception:
            return None

    def delete(self, session_id: str) -> bool:
        if not self._conn:
            return False
        try:
            self._conn.execute(
                "DELETE FROM session_baselines WHERE session_id = ?", (session_id,)
            )
            self._conn.execute(
                "DELETE FROM anomaly_events WHERE session_id = ?", (session_id,)
            )
            self._conn.commit()
            return True
        except Exception:
            return False

    def record_event(
        self, session_id: str, rules: list[str], risk_score: float, action: str
    ) -> None:
        if not self._conn:
            return
        try:
            self._conn.execute(
                "INSERT INTO anomaly_events (session_id, rules, risk_score, action) VALUES (?, ?, ?, ?)",
                (session_id, json.dumps(rules), risk_score, action),
            )
            self._conn.commit()
        except Exception:
            pass

    def get_events(self, session_id: str, limit: int = 100) -> list[dict]:
        if not self._conn:
            return []
        try:
            rows = self._conn.execute(
                "SELECT ts, session_id, rules, risk_score, action FROM anomaly_events WHERE session_id = ? ORDER BY ts DESC LIMIT ?",
                (session_id, limit),
            ).fetchall()
            return [
                {"timestamp": r[0], "session_id": r[1], "rules": json.loads(r[2]),
                 "risk_score": r[3], "action": r[4]}
                for r in rows
            ]
        except Exception:
            return []

    def close(self):
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass


# ── Main detector ─────────────────────────────────────────────────────────────


class AnomalyDetectorService:
    """Session-oriented anomaly detection service.

    Detects 4 primary signals:
      1. Request rate spikes (z-score on rolling per-minute rate)
      2. Error rate spikes (z-score on rolling error ratio)
      3. Model switching patterns (distinct model count in window)
      4. Payload size outliers (z-score + hard bounds)

    Uses z-score with configurable thresholds per sensitivity level.
    Cold start: falls back to simple thresholds until min_baseline_size reached.
    """

    def __init__(
        self,
        sensitivity: str = "medium",
        db_path: str = "",
        window_seconds: int = 300,
    ):
        preset = SENSITIVITY_PRESETS.get(sensitivity, SENSITIVITY_PRESETS["medium"])
        self.sensitivity = sensitivity
        self.window_seconds = window_seconds
        self.z_threshold: float = preset["z_threshold"]
        self.request_rate_threshold: int = preset["request_rate_threshold"]
        self.error_rate_threshold: float = preset["error_rate_threshold"]
        self.model_switch_threshold: int = preset["model_switch_threshold"]
        self.payload_min_chars: int = preset["payload_min_chars"]
        self.payload_max_bytes: int = preset["payload_max_bytes"]
        self.min_baseline_size: int = preset["min_baseline_size"]

        self._lock = Lock()
        self._sessions: dict[str, SessionBaseline] = {}
        self.store = BaselineStore(db_path)

    # ── Public API ────────────────────────────────────────────────────────

    def ingest(
        self,
        session_id: str,
        model: str = "default",
        request_bytes: int = 500,
        status_code: int = 200,
    ) -> None:
        """Record a request into the session baseline."""
        now = time.time()
        record = RequestRecord(
            timestamp=now,
            model=model,
            request_bytes=request_bytes,
            status_code=status_code,
        )

        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionBaseline(session_id=session_id)
                saved = self.store.load(session_id)
                if saved:
                    self._sessions[session_id].request_count = saved.get("request_count", 0)
                    self._sessions[session_id].error_count = saved.get("error_count", 0)

            session = self._sessions[session_id]
            session.request_history.append(record)
            session.payload_sizes.append(request_bytes)
            session.distinct_models.add(model)
            session.last_seen = now
            session.request_count += 1

            if 400 <= status_code < 600:
                session.error_count += 1

            # Rate sample: requests in last minute
            one_min_ago = now - 60.0
            recent = [r for r in session.request_history if r.timestamp >= one_min_ago]
            session.rate_samples.append(len(recent))

            # Error rate sample
            window_reqs = [r for r in session.request_history if now - r.timestamp <= self.window_seconds]
            if window_reqs:
                errors = sum(1 for r in window_reqs if 400 <= r.status_code < 600)
                session.error_rate_samples.append(errors / len(window_reqs))
            else:
                session.error_rate_samples.append(0.0)

    def analyze(
        self,
        session_id: str,
        time_window_minutes: int = 60,
        sensitivity: str = "",
    ) -> dict:
        """Run anomaly analysis on a session.

        Returns:
            {
                "session_id": str,
                "anomalies": [...],
                "risk_score": float,
                "recommended_action": str,
                "baseline_status": str,
            }
        """
        # Temporarily override sensitivity if requested
        orig_z = self.z_threshold
        orig_sensitivity = self.sensitivity
        if sensitivity and sensitivity in SENSITIVITY_PRESETS:
            p = SENSITIVITY_PRESETS[sensitivity]
            self.z_threshold = p["z_threshold"]
            self.sensitivity = sensitivity

        try:
            triggered = self._detect(session_id)
            risk = compute_risk_score(triggered)
            action = recommended_action(risk)
            baseline_status = self._baseline_status(session_id)

            anomalies = []
            for rule in triggered:
                detail = self._rule_detail(session_id, rule)
                anomalies.append({
                    "type": rule,
                    "severity": self._rule_severity(rule, risk),
                    "description": detail.get("description", rule),
                    "score": detail.get("score", risk),
                })

            if triggered:
                self.store.record_event(session_id, triggered, risk, action)

            return {
                "session_id": session_id,
                "anomalies": anomalies,
                "risk_score": risk,
                "recommended_action": action,
                "baseline_status": baseline_status,
            }
        finally:
            self.z_threshold = orig_z
            self.sensitivity = orig_sensitivity

    def get_baselines(self, session_id: str) -> dict:
        """Return current baseline metrics for a session."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                saved = self.store.load(session_id)
                if saved:
                    return {
                        "session_id": session_id,
                        "source": "persisted",
                        "request_count": saved.get("request_count", 0),
                        "error_count": saved.get("error_count", 0),
                        "mean_rate": saved.get("mean_rate", 0.0),
                        "std_rate": saved.get("std_rate", 1.0),
                        "mean_error_rate": saved.get("mean_error_rate", 0.0),
                        "std_error_rate": saved.get("std_error_rate", 0.1),
                        "mean_payload_size": saved.get("mean_payload_size", 0.0),
                        "std_payload_size": saved.get("std_payload_size", 1.0),
                        "distinct_models": json.loads(saved.get("distinct_models", "[]")),
                        "baseline_status": "established" if saved.get("request_count", 0) >= self.min_baseline_size else "warming_up",
                    }
                return {}

            rates = list(session.rate_samples)
            errors = list(session.error_rate_samples)
            payloads = list(session.payload_sizes)

            return {
                "session_id": session_id,
                "source": "live",
                "request_count": session.request_count,
                "error_count": session.error_count,
                "mean_rate": round(float(np.mean(rates)), 3) if rates else 0.0,
                "std_rate": round(float(np.std(rates)), 3) if len(rates) > 1 else 1.0,
                "mean_error_rate": round(float(np.mean(errors)), 4) if errors else 0.0,
                "std_error_rate": round(float(np.std(errors)), 4) if len(errors) > 1 else 0.1,
                "mean_payload_size": round(float(np.mean(payloads)), 1) if payloads else 0.0,
                "std_payload_size": round(float(np.std(payloads)), 1) if len(payloads) > 1 else 1.0,
                "distinct_models": sorted(list(session.distinct_models)),
                "baseline_status": "established" if session.request_count >= self.min_baseline_size else "warming_up",
            }

    def get_report(self, session_id: str) -> dict:
        """Generate detailed report for a session."""
        baselines = self.get_baselines(session_id)
        analysis = self.analyze(session_id)
        events = self.store.get_events(session_id, limit=50)

        return {
            "session_id": session_id,
            "generated_at": time.time(),
            "sensitivity": self.sensitivity,
            "baselines": baselines,
            "analysis": analysis,
            "historical_events": events,
            "summary": {
                "total_requests": baselines.get("request_count", 0),
                "total_errors": baselines.get("error_count", 0),
                "anomaly_count": len(analysis.get("anomalies", [])),
                "risk_score": analysis.get("risk_score", 0.0),
                "recommended_action": analysis.get("recommended_action", "allow"),
                "baseline_status": analysis.get("baseline_status", "insufficient_data"),
            },
        }

    def reset_baseline(self, session_id: str) -> bool:
        """Reset baseline for a session."""
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
        deleted = self.store.delete(session_id)
        return True

    def persist_session(self, session_id: str) -> None:
        """Persist current in-memory baseline to SQLite."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                self.store.save(session_id, session)

    # ── Detection internals ───────────────────────────────────────────────

    def _detect(self, session_id: str) -> list[str]:
        """Run all 4 detection signals, return triggered rule names."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return []

            triggered = []
            now = time.time()

            if self._check_request_rate(session, now):
                triggered.append("request_rate_spike")

            if self._check_error_rate(session, now):
                triggered.append("error_rate_spike")

            if self._check_model_switching(session, now):
                triggered.append("model_switching")

            if self._check_payload_size(session):
                triggered.append("payload_size_anomaly")

            return triggered

    def _has_baseline(self, session: SessionBaseline) -> bool:
        return session.request_count >= self.min_baseline_size

    @staticmethod
    def _zscore(value: float, mean: float, std: float) -> float:
        if std < 1e-6:
            return 0.0
        return (value - mean) / std

    def _check_request_rate(self, session: SessionBaseline, now: float) -> bool:
        """Signal 1: Request rate spike."""
        one_min_ago = now - 60.0
        recent = [r for r in session.request_history if r.timestamp >= one_min_ago]
        current_rate = len(recent)

        if self._has_baseline(session) and len(session.rate_samples) >= 5:
            mean_rate = float(np.mean(session.rate_samples))
            std_rate = float(np.std(session.rate_samples))
            z = self._zscore(current_rate, mean_rate, std_rate)
            return z > self.z_threshold
        else:
            return current_rate > self.request_rate_threshold

    def _check_error_rate(self, session: SessionBaseline, now: float) -> bool:
        """Signal 2: Error rate spike."""
        window_reqs = [r for r in session.request_history if now - r.timestamp <= self.window_seconds]
        if not window_reqs:
            return False
        errors = sum(1 for r in window_reqs if 400 <= r.status_code < 600)
        error_rate = errors / len(window_reqs)

        if self._has_baseline(session) and len(session.error_rate_samples) >= 5:
            mean_err = float(np.mean(session.error_rate_samples))
            std_err = float(np.std(session.error_rate_samples))
            if std_err < 0.01:
                std_err = 0.01
            z = self._zscore(error_rate, mean_err, std_err)
            return z > self.z_threshold
        else:
            return error_rate > self.error_rate_threshold

    def _check_model_switching(self, session: SessionBaseline, now: float) -> bool:
        """Signal 3: Excessive model switching."""
        window_reqs = [r for r in session.request_history if now - r.timestamp <= self.window_seconds]
        distinct = len(set(r.model for r in window_reqs))
        return distinct > self.model_switch_threshold

    def _check_payload_size(self, session: SessionBaseline) -> bool:
        """Signal 4: Payload size outlier."""
        if not session.payload_sizes:
            return False

        latest = session.payload_sizes[-1]

        # Hard bounds
        if latest < self.payload_min_chars or latest > self.payload_max_bytes:
            return True

        # Z-score on payload sizes
        if self._has_baseline(session) and len(session.payload_sizes) >= 10:
            mean_p = float(np.mean(session.payload_sizes))
            std_p = float(np.std(session.payload_sizes))
            if std_p > 1.0:
                z = self._zscore(latest, mean_p, std_p)
                if abs(z) > self.z_threshold:
                    return True

        return False

    def _baseline_status(self, session_id: str) -> str:
        """Determine baseline status for a session."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                saved = self.store.load(session_id)
                if not saved:
                    return "insufficient_data"
                if saved.get("request_count", 0) >= self.min_baseline_size:
                    return "established"
                return "warming_up"
            if session.request_count >= self.min_baseline_size:
                return "established"
            if session.request_count > 0:
                return "warming_up"
            return "insufficient_data"

    def _rule_severity(self, rule: str, risk: float) -> str:
        if risk >= 0.7:
            return "high"
        if risk >= 0.3:
            return "medium"
        return "low"

    def _rule_detail(self, session_id: str, rule: str) -> dict:
        """Get description and score for a triggered rule."""
        session = self._sessions.get(session_id)
        if not session:
            return {"description": rule, "score": 0.0}

        now = time.time()
        weight = _RULE_WEIGHTS.get(rule, 0.05)

        if rule == "request_rate_spike":
            one_min_ago = now - 60.0
            recent = [r for r in session.request_history if r.timestamp >= one_min_ago]
            rate = len(recent)
            return {
                "description": f"Request rate {rate}/min exceeds threshold ({self.request_rate_threshold}/min)",
                "score": weight,
            }

        if rule == "error_rate_spike":
            window_reqs = [r for r in session.request_history if now - r.timestamp <= self.window_seconds]
            if window_reqs:
                errors = sum(1 for r in window_reqs if 400 <= r.status_code < 600)
                rate = errors / len(window_reqs)
                return {
                    "description": f"Error rate {rate*100:.1f}% exceeds threshold ({self.error_rate_threshold*100:.0f}%)",
                    "score": weight,
                }
            return {"description": "Error rate spike detected", "score": weight}

        if rule == "model_switching":
            window_reqs = [r for r in session.request_history if now - r.timestamp <= self.window_seconds]
            distinct = len(set(r.model for r in window_reqs))
            return {
                "description": f"{distinct} distinct models in {self.window_seconds}s window (threshold: {self.model_switch_threshold})",
                "score": weight,
            }

        if rule == "payload_size_anomaly":
            latest = session.payload_sizes[-1] if session.payload_sizes else 0
            return {
                "description": f"Payload size {latest} bytes outside expected range [{self.payload_min_chars}, {self.payload_max_bytes}]",
                "score": weight,
            }

        return {"description": rule, "score": weight}


# ── Module-level singleton ────────────────────────────────────────────────────

_detector: Optional[AnomalyDetectorService] = None
_detector_lock = Lock()


def get_detector(
    sensitivity: str = "medium",
    db_path: str = "",
) -> AnomalyDetectorService:
    """Get or create the singleton detector instance."""
    global _detector
    with _detector_lock:
        if _detector is None:
            _detector = AnomalyDetectorService(
                sensitivity=sensitivity,
                db_path=db_path,
            )
        return _detector


def reset_detector() -> None:
    """Reset the singleton (for testing)."""
    global _detector
    with _detector_lock:
        _detector = None
