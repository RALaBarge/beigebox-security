"""API Anomaly Detection endpoints.

Exposes z-score based anomaly detection for API session analysis.
Detects 4 signals: request rate spikes, error rate spikes,
model switching patterns, and payload size outliers.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from beigebox_security.config import get_config
from beigebox_security.integrations.anomaly import (
    AnomalyDetectorService,
    get_detector,
)

router = APIRouter()


# ── Request / Response models ─────────────────────────────────────────────────


class AnalyzeSessionRequest(BaseModel):
    """Request to analyze session for anomalies."""

    session_id: str
    """Session ID to analyze."""

    time_window_minutes: int = Field(default=60, ge=1, le=1440)
    """Look-back window for anomaly detection (minutes)."""

    sensitivity: str = Field(default="medium", pattern="^(low|medium|high)$")
    """Detection sensitivity: low, medium, high."""


class AnomalyFinding(BaseModel):
    """A single detected anomaly."""

    type: str
    """Signal type: request_rate_spike, error_rate_spike, model_switching, payload_size_anomaly."""

    severity: str
    """Severity: low, medium, high."""

    description: str
    """Human-readable description of the anomaly."""

    score: float
    """Anomaly score contribution (0-1)."""


class AnalyzeSessionResponse(BaseModel):
    """Response from anomaly analysis."""

    session_id: str
    anomalies: list[AnomalyFinding]
    risk_score: float
    recommended_action: str
    baseline_status: str


class BaselineResponse(BaseModel):
    """Baseline metrics for a session."""

    session_id: str
    source: str = "live"
    request_count: int = 0
    error_count: int = 0
    mean_rate: float = 0.0
    std_rate: float = 1.0
    mean_error_rate: float = 0.0
    std_error_rate: float = 0.1
    mean_payload_size: float = 0.0
    std_payload_size: float = 1.0
    distinct_models: list[str] = []
    baseline_status: str = "insufficient_data"


class ResetBaselineResponse(BaseModel):
    """Response from baseline reset."""

    session_id: str
    status: str
    message: str


class ReportSummary(BaseModel):
    """Summary section of the report."""

    total_requests: int = 0
    total_errors: int = 0
    anomaly_count: int = 0
    risk_score: float = 0.0
    recommended_action: str = "allow"
    baseline_status: str = "insufficient_data"


class SessionReport(BaseModel):
    """Detailed session report."""

    session_id: str
    generated_at: float
    sensitivity: str
    baselines: dict
    analysis: dict
    historical_events: list[dict]
    summary: ReportSummary


# ── Helper ────────────────────────────────────────────────────────────────────


def _get_detector() -> AnomalyDetectorService:
    """Get detector instance using config."""
    config = get_config()
    return get_detector(
        sensitivity=config.anomaly_detection_sensitivity,
        db_path=config.anomaly_detection_db_path,
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("/analyze", response_model=AnalyzeSessionResponse)
async def analyze_session(request: AnalyzeSessionRequest):
    """
    Analyze a session for suspicious API patterns.

    Detects token extraction attempts via anomalous request rates,
    error rates, model switching, and payload sizes.
    Uses z-score deviation from rolling baselines with configurable
    sensitivity (low/medium/high).
    """
    detector = _get_detector()
    result = detector.analyze(
        session_id=request.session_id,
        time_window_minutes=request.time_window_minutes,
        sensitivity=request.sensitivity,
    )

    anomalies = [
        AnomalyFinding(
            type=a["type"],
            severity=a["severity"],
            description=a["description"],
            score=a["score"],
        )
        for a in result.get("anomalies", [])
    ]

    return AnalyzeSessionResponse(
        session_id=result["session_id"],
        anomalies=anomalies,
        risk_score=result["risk_score"],
        recommended_action=result["recommended_action"],
        baseline_status=result["baseline_status"],
    )


@router.get("/report/{session_id}", response_model=SessionReport)
async def get_report(
    session_id: str,
    format: str = Query(default="json", pattern="^(json|html|pdf)$"),
):
    """
    Get detailed anomaly report for a session.

    Includes baselines, current analysis, and historical events.
    Supports json format (html/pdf planned).
    """
    detector = _get_detector()
    report = detector.get_report(session_id)

    if not report.get("baselines"):
        raise HTTPException(
            status_code=404,
            detail=f"No data found for session '{session_id}'",
        )

    summary = ReportSummary(**report.get("summary", {}))

    return SessionReport(
        session_id=report["session_id"],
        generated_at=report["generated_at"],
        sensitivity=report["sensitivity"],
        baselines=report["baselines"],
        analysis=report["analysis"],
        historical_events=report["historical_events"],
        summary=summary,
    )


@router.get("/baselines/{session_id}", response_model=BaselineResponse)
async def get_baselines(session_id: str):
    """
    Get current baseline metrics for a session.

    Returns rolling statistics used for z-score calculations:
    mean/std for request rate, error rate, and payload sizes.
    """
    detector = _get_detector()
    baselines = detector.get_baselines(session_id)

    if not baselines:
        raise HTTPException(
            status_code=404,
            detail=f"No baselines found for session '{session_id}'",
        )

    return BaselineResponse(**baselines)


@router.post("/reset-baseline/{session_id}", response_model=ResetBaselineResponse)
async def reset_baseline(session_id: str):
    """
    Reset baseline for a session (start fresh).

    Clears all in-memory and persisted baseline data for the session.
    The next requests will begin a new warm-up period.
    """
    detector = _get_detector()
    detector.reset_baseline(session_id)

    return ResetBaselineResponse(
        session_id=session_id,
        status="reset",
        message=f"Baseline for session '{session_id}' has been reset. New baseline will begin warming up on next request.",
    )
