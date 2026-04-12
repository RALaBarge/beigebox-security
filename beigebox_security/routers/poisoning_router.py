"""RAG Poisoning Detection endpoints."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from beigebox_security.integrations.poisoning import get_service, RAGPoisoningDetector

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

VALID_METHODS = sorted(RAGPoisoningDetector.VALID_METHODS)


class DetectPoisoningRequest(BaseModel):
    """Request to detect poisoning in embeddings."""

    embeddings: list[list[float]]
    """List of embedding vectors."""

    method: str = Field(
        default="hybrid",
        description=f"Detection method: {', '.join(VALID_METHODS)}",
    )

    sensitivity: float = Field(
        default=3.0,
        ge=0.0,
        le=10.0,
        description="Z-score threshold for anomaly detection (higher = less sensitive)",
    )

    collection_id: str = Field(
        default="default",
        min_length=1,
        max_length=256,
        description="Collection ID for baseline lookup",
    )


class DetectPoisoningResponse(BaseModel):
    """Response from poisoning detection."""

    poisoned: list[bool]
    """Boolean flags per embedding."""

    scores: list[float]
    """Anomaly scores per embedding (0-1)."""

    confidence: float
    """Overall confidence in detection (0-1)."""

    method_used: str
    """Detection method used."""


class ScanRequest(BaseModel):
    """Request to scan a full collection."""

    collection_id: str = Field(default="default", min_length=1, max_length=256)
    embeddings: list[list[float]]
    method: str = "hybrid"
    sensitivity: float = Field(default=3.0, ge=0.0, le=10.0)


class ScanResponse(BaseModel):
    """Response from a full collection scan."""

    collection_id: str
    total: int
    flagged: int
    flagged_indices: list[int]
    method_used: str


class BaselineResponse(BaseModel):
    """Baseline statistics for a collection."""

    collection_id: str
    count: int
    mean_norm: float
    std_norm: float
    z_threshold: float
    baseline_window_size: int
    min_norm_range: float
    max_norm_range: float


class UpdateBaselineRequest(BaseModel):
    """Request to update a collection baseline."""

    embeddings: list[list[float]]
    sensitivity: float = Field(default=3.0, ge=0.0, le=10.0)


class ErrorResponse(BaseModel):
    """Structured error."""

    error: str
    detail: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sensitivity_param_to_detector(sensitivity: float) -> float:
    """
    Map the user-facing sensitivity (z-score threshold style, 0-10)
    to the detector's internal sensitivity (0-1 range).

    User passes ~3.0 meaning z-score threshold ~3 (95% confidence).
    Detector expects 0.95 for that.
    """
    # Rough inverse of _sensitivity_to_z_threshold:
    # z=2.0 -> sens=0.90, z=3.0 -> sens=0.945, z=4.0 -> sens=0.99
    if sensitivity <= 2.0:
        return 0.90
    if sensitivity >= 4.0:
        return 0.99
    return 0.90 + (sensitivity - 2.0) / 2.0 * 0.09


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/detect", response_model=DetectPoisoningResponse)
async def detect_poisoning(request: DetectPoisoningRequest):
    """
    Detect poisoning in embedding vectors.

    Uses anomaly detection to identify potentially poisoned embeddings
    that deviate from expected baselines.
    """
    try:
        svc = get_service()
        internal_sens = _sensitivity_param_to_detector(request.sensitivity)
        result = svc.detect(
            embeddings=request.embeddings,
            method=request.method,
            sensitivity=internal_sens,
            collection_id=request.collection_id,
        )
        return DetectPoisoningResponse(**result)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Detection failed: {exc}")


@router.post("/scan", response_model=ScanResponse)
async def scan_collection(request: ScanRequest):
    """
    Scan entire collection for poisoned embeddings.

    Builds a baseline from provided embeddings, then flags anomalies.
    """
    try:
        svc = get_service()
        internal_sens = _sensitivity_param_to_detector(request.sensitivity)
        result = svc.scan_collection(
            collection_id=request.collection_id,
            embeddings=request.embeddings,
            method=request.method,
            sensitivity=internal_sens,
        )
        return ScanResponse(**result)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}")


@router.get("/baselines/{collection_id}", response_model=BaselineResponse)
async def get_baseline(collection_id: str):
    """
    Get current baseline statistics for a collection.
    """
    svc = get_service()
    stats = svc.get_baseline(collection_id)
    if stats is None:
        raise HTTPException(
            status_code=404,
            detail=f"No baseline found for collection '{collection_id}'",
        )
    return BaselineResponse(**stats)


@router.post("/baselines/{collection_id}", response_model=BaselineResponse)
async def update_baseline(collection_id: str, request: UpdateBaselineRequest):
    """
    Update baseline for a collection with known-good embeddings.
    """
    if not request.embeddings:
        raise HTTPException(status_code=422, detail="Embeddings list cannot be empty")

    try:
        svc = get_service()
        internal_sens = _sensitivity_param_to_detector(request.sensitivity)
        stats = svc.update_baseline(
            collection_id=collection_id,
            embeddings=request.embeddings,
            sensitivity=internal_sens,
        )
        stats["collection_id"] = collection_id
        return BaselineResponse(**stats)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Baseline update failed: {exc}")


@router.delete("/baselines/{collection_id}")
async def reset_baseline(collection_id: str):
    """
    Reset baseline for a collection.
    """
    svc = get_service()
    svc.reset_baseline(collection_id)
    return {"status": "ok", "collection_id": collection_id}
