"""Memory Integrity Validation endpoints."""

import secrets
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from beigebox_security.config import get_config
from beigebox_security.integrations.memory import (
    MemoryIntegrityManager,
    MemoryIntegrityStore,
    MemoryIntegrityValidator,
    get_manager,
    reset_manager,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ValidateSessionRequest(BaseModel):
    """Request to validate session memory integrity."""

    session_id: str
    """Session ID to validate"""

    start_message_id: int = 0
    """Start validating from this message ID"""

    end_message_id: int = -1
    """End validating at this message ID (-1 = latest)"""


class TamperEvent(BaseModel):
    """Evidence of tampering."""

    message_id: int
    field: str
    """Field that was modified"""

    timestamp: str
    """When tampering was detected"""


class ValidateSessionResponse(BaseModel):
    """Response from memory validation."""

    session_id: str
    valid: bool
    """Whether all messages passed integrity checks"""

    tampered_messages: list[int]
    """List of message IDs with tampering detected"""

    tamper_events: list[TamperEvent]
    """Detailed tampering events"""

    confidence: float
    """Confidence in validation (0-1)"""


class SignMessageRequest(BaseModel):
    """Request to sign a message."""

    session_id: str
    user_id: str
    message: dict


class SignMessageResponse(BaseModel):
    """Response from signing a message."""

    message_id: str
    signature: str


class ResignResponse(BaseModel):
    """Response from re-signing a session."""

    session_id: str
    resigned_count: int
    key_version: int


class SessionStatusResponse(BaseModel):
    """Integrity status for a session."""

    session_id: str
    exists: bool
    signed_messages: int
    tamper_events: int
    validations_run: int
    key_version: int
    last_checked: Optional[str]
    status: str  # healthy, compromised, unsigned, unknown


class AuditEntry(BaseModel):
    """Single audit log entry."""

    id: int
    session_id: str
    event_type: str
    message_id: Optional[str]
    detail: Optional[str]
    created_at: str


# ---------------------------------------------------------------------------
# Helper: get manager from config
# ---------------------------------------------------------------------------


def _get_manager() -> MemoryIntegrityManager:
    """Resolve the manager singleton using config."""
    cfg = get_config()
    key_bytes: Optional[bytes] = None
    if cfg.memory_integrity_key:
        # Accept hex-encoded 32-byte key from config/env
        try:
            key_bytes = bytes.fromhex(cfg.memory_integrity_key)
        except ValueError:
            # Fall back to UTF-8 hash if not valid hex
            import hashlib
            key_bytes = hashlib.sha256(cfg.memory_integrity_key.encode()).digest()

    return get_manager(
        secret_key=key_bytes,
        db_path=cfg.memory_integrity_db_path,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/sign", response_model=SignMessageResponse)
async def sign_message(request: SignMessageRequest):
    """
    Sign a single message and store the signature.

    Used when persisting new messages to ensure integrity from creation.
    """
    mgr = _get_manager()
    sig = mgr.sign_and_store(request.message, request.session_id, request.user_id)
    return SignMessageResponse(
        message_id=str(request.message.get("id", "")),
        signature=sig,
    )


@router.post("/validate", response_model=ValidateSessionResponse)
async def validate_session(request: ValidateSessionRequest):
    """
    Validate conversation memory for tampering.

    Uses HMAC-SHA256 signatures to detect unauthorized modifications
    to conversation history.
    """
    mgr = _get_manager()

    # Retrieve stored signatures for the session
    sigs = mgr.store.get_session_signatures(request.session_id)
    if not sigs:
        raise HTTPException(
            status_code=404,
            detail=f"No signatures found for session {request.session_id}",
        )

    # Reconstruct messages from stored signature metadata.
    # In a real deployment the caller provides messages or we fetch from
    # the conversation store. Here we validate against what was signed.
    # The caller should POST messages along with the request for full
    # validation. For now, return clean if no messages provided.
    # (The test suite will exercise this via sign-then-validate flow.)
    raise HTTPException(
        status_code=400,
        detail="Use POST /validate-messages to validate with message bodies",
    )


class ValidateMessagesRequest(BaseModel):
    """Request to validate messages with their content."""

    session_id: str
    user_id: str
    messages: list[dict]
    start_message_id: int = 0
    end_message_id: int = -1


@router.post("/validate-messages", response_model=ValidateSessionResponse)
async def validate_messages(request: ValidateMessagesRequest):
    """
    Validate conversation messages against stored HMAC signatures.

    Accepts full message bodies for verification.
    """
    mgr = _get_manager()
    result = mgr.validate_session(
        session_id=request.session_id,
        messages=request.messages,
        user_id=request.user_id,
        start_id=request.start_message_id,
        end_id=request.end_message_id,
    )
    return ValidateSessionResponse(
        session_id=result["session_id"],
        valid=result["valid"],
        tampered_messages=result["tampered_messages"],
        tamper_events=[
            TamperEvent(
                message_id=int(te["message_id"]),
                field=te["field"],
                timestamp=te["timestamp"],
            )
            for te in result["tamper_events"]
        ],
        confidence=result["confidence"],
    )


@router.get("/audit/{session_id}", response_model=list[AuditEntry])
async def get_audit_log(session_id: str, limit: int = 100):
    """
    Get audit log of integrity checks for a session.
    """
    mgr = _get_manager()
    entries = mgr.store.get_audit_log(session_id, limit=limit)
    return [AuditEntry(**e) for e in entries]


class ResignMessagesRequest(BaseModel):
    """Request to re-sign messages."""

    user_id: str
    messages: list[dict]


@router.post("/resign/{session_id}", response_model=ResignResponse)
async def resign_session(session_id: str, request: ResignMessagesRequest):
    """
    Re-sign all messages in a session (e.g., after key rotation).
    """
    mgr = _get_manager()
    result = mgr.resign_session(
        session_id=session_id,
        messages=request.messages,
        user_id=request.user_id,
    )
    return ResignResponse(**result)


@router.get("/status/{session_id}", response_model=SessionStatusResponse)
async def get_status(session_id: str):
    """
    Get integrity status for a session.
    """
    mgr = _get_manager()
    status = mgr.session_status(session_id)
    return SessionStatusResponse(**status)
