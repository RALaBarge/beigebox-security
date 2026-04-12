"""
Memory integrity integration layer.

Self-contained HMAC-SHA256 signing/verification with SQLite-backed
storage for signatures and audit logs. No dependency on the beigebox
core package — all crypto primitives are inline.
"""

import hashlib
import hmac
import json
import logging
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Fields included in the HMAC signature.
SIGNABLE_FIELDS = frozenset({
    "id", "conversation_id", "role", "content", "model",
    "timestamp", "token_count",
})


class MemoryIntegrityStore:
    """SQLite storage for HMAC signatures and audit logs."""

    def __init__(self, db_path: str = "./data/memory_integrity.db"):
        self.db_path = db_path
        self._local = threading.local()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS message_signatures (
                message_id   TEXT PRIMARY KEY,
                session_id   TEXT NOT NULL,
                signature    TEXT NOT NULL,
                key_version  INTEGER NOT NULL DEFAULT 1,
                signed_at    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sig_session
                ON message_signatures(session_id);

            CREATE TABLE IF NOT EXISTS audit_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id   TEXT NOT NULL,
                event_type   TEXT NOT NULL,
                message_id   TEXT,
                detail       TEXT,
                created_at   TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_session
                ON audit_log(session_id);

            CREATE TABLE IF NOT EXISTS sessions (
                session_id    TEXT PRIMARY KEY,
                user_id       TEXT NOT NULL,
                key_version   INTEGER NOT NULL DEFAULT 1,
                created_at    TEXT NOT NULL,
                last_checked  TEXT
            );
        """)
        conn.commit()

    # ---- signatures ----

    def store_signature(
        self,
        message_id: str,
        session_id: str,
        signature: str,
        key_version: int = 1,
    ) -> None:
        conn = self._get_conn()
        conn.execute(
            """INSERT OR REPLACE INTO message_signatures
               (message_id, session_id, signature, key_version, signed_at)
               VALUES (?, ?, ?, ?, ?)""",
            (message_id, session_id, signature, key_version,
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    def get_signature(self, message_id: str) -> Optional[dict]:
        row = self._get_conn().execute(
            "SELECT * FROM message_signatures WHERE message_id = ?",
            (message_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_session_signatures(self, session_id: str) -> dict[str, str]:
        """Return {message_id: signature} for a session."""
        rows = self._get_conn().execute(
            "SELECT message_id, signature FROM message_signatures WHERE session_id = ?",
            (session_id,),
        ).fetchall()
        return {r["message_id"]: r["signature"] for r in rows}

    def delete_session_signatures(self, session_id: str) -> int:
        conn = self._get_conn()
        cur = conn.execute(
            "DELETE FROM message_signatures WHERE session_id = ?",
            (session_id,),
        )
        conn.commit()
        return cur.rowcount

    # ---- audit log ----

    def log_event(
        self,
        session_id: str,
        event_type: str,
        message_id: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> None:
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO audit_log (session_id, event_type, message_id, detail, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (session_id, event_type, message_id, detail,
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    def get_audit_log(self, session_id: str, limit: int = 100) -> list[dict]:
        rows = self._get_conn().execute(
            """SELECT id, session_id, event_type, message_id, detail, created_at
               FROM audit_log WHERE session_id = ? ORDER BY id DESC LIMIT ?""",
            (session_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    # ---- sessions ----

    def ensure_session(self, session_id: str, user_id: str, key_version: int = 1) -> None:
        conn = self._get_conn()
        conn.execute(
            """INSERT OR IGNORE INTO sessions (session_id, user_id, key_version, created_at)
               VALUES (?, ?, ?, ?)""",
            (session_id, user_id, key_version,
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    def get_session(self, session_id: str) -> Optional[dict]:
        row = self._get_conn().execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,),
        ).fetchone()
        return dict(row) if row else None

    def update_session_checked(self, session_id: str) -> None:
        conn = self._get_conn()
        conn.execute(
            "UPDATE sessions SET last_checked = ? WHERE session_id = ?",
            (datetime.now(timezone.utc).isoformat(), session_id),
        )
        conn.commit()

    def update_session_key_version(self, session_id: str, key_version: int) -> None:
        conn = self._get_conn()
        conn.execute(
            "UPDATE sessions SET key_version = ? WHERE session_id = ?",
            (key_version, session_id),
        )
        conn.commit()

    def get_signature_count(self, session_id: str) -> int:
        row = self._get_conn().execute(
            "SELECT COUNT(*) as cnt FROM message_signatures WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        return row["cnt"] if row else 0


class MemoryIntegrityValidator:
    """
    HMAC-SHA256 signing and verification for conversation messages.

    Self-contained — does not depend on beigebox core.
    """

    def __init__(self, secret_key: bytes):
        if not isinstance(secret_key, bytes) or len(secret_key) != 32:
            raise ValueError("secret_key must be exactly 32 bytes")
        self._key = secret_key

    def sign_message(self, message: dict, user_id: str) -> str:
        """Generate HMAC-SHA256 hex digest for a message."""
        signable = {k: v for k, v in message.items() if k in SIGNABLE_FIELDS}
        canonical = json.dumps(signable, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        conv_id = message.get("conversation_id", "")
        signing_input = f"{user_id}|{conv_id}|{canonical}"
        h = hmac.new(self._key, signing_input.encode("utf-8"), hashlib.sha256)
        return h.hexdigest()

    def verify_message(self, message: dict, user_id: str, signature: str) -> bool:
        """Verify HMAC signature (constant-time comparison)."""
        try:
            expected = self.sign_message(message, user_id)
            return hmac.compare_digest(expected, signature)
        except Exception:
            return False

    @staticmethod
    def is_valid_signature_format(sig: str) -> bool:
        if not isinstance(sig, str) or len(sig) != 64:
            return False
        try:
            int(sig, 16)
            return True
        except ValueError:
            return False


class MemoryIntegrityManager:
    """
    High-level orchestrator: ties validator + store together.

    Provides sign, verify, validate-session, resign, audit, status.
    """

    def __init__(
        self,
        secret_key: bytes,
        store: MemoryIntegrityStore,
        key_version: int = 1,
    ):
        self._validator = MemoryIntegrityValidator(secret_key)
        self._store = store
        self._key_version = key_version

    @property
    def store(self) -> MemoryIntegrityStore:
        return self._store

    # ---- signing ----

    def sign_and_store(
        self,
        message: dict,
        session_id: str,
        user_id: str,
    ) -> str:
        """Sign a message and persist the signature."""
        sig = self._validator.sign_message(message, user_id)
        msg_id = str(message.get("id", ""))
        self._store.ensure_session(session_id, user_id, self._key_version)
        self._store.store_signature(msg_id, session_id, sig, self._key_version)
        self._store.log_event(session_id, "sign", msg_id)
        return sig

    # ---- verification ----

    def verify_message(self, message: dict, user_id: str, stored_sig: str) -> bool:
        return self._validator.verify_message(message, user_id, stored_sig)

    def validate_session(
        self,
        session_id: str,
        messages: list[dict],
        user_id: str,
        start_id: int = 0,
        end_id: int = -1,
    ) -> dict:
        """
        Validate all (or a range of) messages in a session.

        Returns structured result dict.
        """
        t0 = time.monotonic()

        sigs = self._store.get_session_signatures(session_id)

        # Filter range
        if end_id >= 0:
            messages = [m for m in messages if start_id <= int(m.get("id", 0)) <= end_id]
        elif start_id > 0:
            messages = [m for m in messages if int(m.get("id", 0)) >= start_id]

        tampered: list[dict] = []
        unsigned: list[str] = []

        for msg in messages:
            msg_id = str(msg.get("id", ""))
            stored_sig = sigs.get(msg_id)

            if not stored_sig:
                unsigned.append(msg_id)
                continue

            if not self._validator.verify_message(msg, user_id, stored_sig):
                tampered.append({
                    "message_id": msg_id,
                    "field": "content",  # most common tamper target
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                self._store.log_event(
                    session_id, "tamper_detected", msg_id,
                    detail="signature_mismatch",
                )

        elapsed = (time.monotonic() - t0) * 1000
        valid = len(tampered) == 0

        # Confidence: 1.0 if all signed, reduced proportionally by unsigned messages
        total = len(messages)
        signed_count = total - len(unsigned)
        confidence = signed_count / total if total > 0 else 0.0

        self._store.log_event(
            session_id,
            "validation_pass" if valid else "validation_fail",
            detail=f"checked={total} tampered={len(tampered)} unsigned={len(unsigned)}",
        )
        self._store.update_session_checked(session_id)

        return {
            "session_id": session_id,
            "valid": valid,
            "tampered_messages": [int(t["message_id"]) for t in tampered],
            "tamper_events": tampered,
            "unsigned_messages": unsigned,
            "total_checked": total,
            "confidence": round(confidence, 4),
            "elapsed_ms": round(elapsed, 2),
        }

    # ---- re-signing ----

    def resign_session(
        self,
        session_id: str,
        messages: list[dict],
        user_id: str,
    ) -> dict:
        """Re-sign all messages (key rotation)."""
        new_version = self._key_version
        resigned = 0
        for msg in messages:
            msg_id = str(msg.get("id", ""))
            sig = self._validator.sign_message(msg, user_id)
            self._store.store_signature(msg_id, session_id, sig, new_version)
            resigned += 1

        self._store.update_session_key_version(session_id, new_version)
        self._store.log_event(
            session_id, "resign",
            detail=f"resigned={resigned} key_version={new_version}",
        )

        return {
            "session_id": session_id,
            "resigned_count": resigned,
            "key_version": new_version,
        }

    # ---- status ----

    def session_status(self, session_id: str) -> dict:
        session = self._store.get_session(session_id)
        sig_count = self._store.get_signature_count(session_id)

        # Count recent audit events
        audit = self._store.get_audit_log(session_id, limit=500)
        tamper_count = sum(1 for e in audit if e["event_type"] == "tamper_detected")
        validation_count = sum(
            1 for e in audit if e["event_type"] in ("validation_pass", "validation_fail")
        )

        if session is None:
            return {
                "session_id": session_id,
                "exists": False,
                "signed_messages": 0,
                "tamper_events": 0,
                "validations_run": 0,
                "key_version": 0,
                "last_checked": None,
                "status": "unknown",
            }

        if tamper_count > 0:
            status = "compromised"
        elif sig_count == 0:
            status = "unsigned"
        else:
            status = "healthy"

        return {
            "session_id": session_id,
            "exists": True,
            "signed_messages": sig_count,
            "tamper_events": tamper_count,
            "validations_run": validation_count,
            "key_version": session.get("key_version", 1),
            "last_checked": session.get("last_checked"),
            "status": status,
        }


# ---------------------------------------------------------------------------
# Module-level singleton management
# ---------------------------------------------------------------------------

_manager: Optional[MemoryIntegrityManager] = None
_lock = threading.Lock()


def get_manager(
    secret_key: Optional[bytes] = None,
    db_path: str = "./data/memory_integrity.db",
    key_version: int = 1,
) -> MemoryIntegrityManager:
    """Get or create the singleton manager."""
    global _manager
    if _manager is not None:
        return _manager
    with _lock:
        if _manager is not None:
            return _manager
        if secret_key is None:
            secret_key = secrets.token_bytes(32)
            logger.warning("No secret_key provided — generated ephemeral key (not persistent)")
        store = MemoryIntegrityStore(db_path)
        _manager = MemoryIntegrityManager(secret_key, store, key_version)
        return _manager


def reset_manager() -> None:
    """Reset singleton (for testing)."""
    global _manager
    _manager = None
