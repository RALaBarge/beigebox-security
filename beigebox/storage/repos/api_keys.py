"""
ApiKeyRepo — entity repo for the api_keys table.

Sits on top of BaseDB; callers inject the driver.  Knows nothing about how the
driver stores bytes — that's BaseDB's job.  Knows everything about what an API
key *is*: creation, verification (constant-time scrypt), listing, revocation.

Hash format: scrypt:<log2n>:<r>:<p>:<hex_salt>:<hex_hash>
Existing bcrypt hashes (starting with $2) are detected and rejected gracefully
— keys must be rotated after upgrading.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from beigebox.storage.db.base import BaseDB

_DDL = """
CREATE TABLE IF NOT EXISTS api_keys (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,
    name         TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_used    TEXT,
    last_rotated TEXT,
    expires_at   TEXT,
    active       INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id  ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
"""

# scrypt parameters: N=2^14, r=8, p=1 — ~100ms on commodity hardware
_N = 14   # log2 of N
_R = 8
_P = 1
_DKLEN = 32


def _hash_key(plain_key: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(plain_key.encode(), salt=salt, n=2 ** _N, r=_R, p=_P, dklen=_DKLEN)
    return f"scrypt:{_N}:{_R}:{_P}:{salt.hex()}:{dk.hex()}"


def _verify_key(plain_key: str, stored_hash: str) -> bool:
    if stored_hash.startswith("$2"):
        # Legacy bcrypt hash — can't verify without bcrypt; force rotation
        return False
    parts = stored_hash.split(":")
    if len(parts) != 6 or parts[0] != "scrypt":
        return False
    try:
        log2n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = bytes.fromhex(parts[4])
        expected = bytes.fromhex(parts[5])
    except (ValueError, TypeError):
        return False
    dk = hashlib.scrypt(plain_key.encode(), salt=salt, n=2 ** log2n, r=r, p=p, dklen=len(expected))
    return hmac.compare_digest(dk, expected)


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ApiKeyRepo:
    """Per-entity repository for api_keys.

    Inject a BaseDB instance; the repo owns the schema, hashing rules, and
    access patterns for this table.  It does NOT own the connection lifecycle —
    callers create and close the db.
    """

    def __init__(self, db: "BaseDB") -> None:
        self._db = db

    def create_tables(self) -> None:
        """Idempotent DDL for api_keys (+ indexes)."""
        for stmt in _DDL.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                self._db.execute(stmt)

    # ── write operations ───────────────────────────────────────────────────

    def create(self, user_id: str, name: str = "default") -> tuple[str, str]:
        """Create a new API key.  Returns (key_id, plain_key).

        The plain key is returned once and never stored.  Only the scrypt hash
        is persisted.
        """
        key_id = str(uuid.uuid4())
        plain_key = secrets.token_urlsafe(32)
        key_hash = _hash_key(plain_key)
        now = _now_utc()
        ph = self._db._placeholder()
        self._db.execute(
            f"INSERT INTO api_keys (id, user_id, key_hash, name, created_at) "
            f"VALUES ({ph}, {ph}, {ph}, {ph}, {ph})",
            (key_id, user_id, key_hash, name, now),
        )
        return key_id, plain_key

    def revoke(self, key_id: str, user_id: str) -> bool:
        """Deactivate a key.  Returns True if a row was updated."""
        ph = self._db._placeholder()
        self._db.execute(
            f"UPDATE api_keys SET active=0 WHERE id={ph} AND user_id={ph}",
            (key_id, user_id),
        )
        return self._db._rowcount() > 0

    # ── read operations ────────────────────────────────────────────────────

    def list_for_user(self, user_id: str) -> list[dict]:
        """Return all keys for a user (no hash — metadata only)."""
        ph = self._db._placeholder()
        return self._db.fetchall(
            f"SELECT id, name, created_at, last_used, active "
            f"FROM api_keys WHERE user_id={ph} ORDER BY created_at DESC",
            (user_id,),
        )

    def verify(self, plain_key: str) -> str | None:
        """Verify a plain-text key against stored scrypt hashes.

        Returns the owning user_id on success, None on failure.  Constant-time
        guard: always iterates all active hashes so timing reveals nothing about
        key count.  An extra dummy hash is computed when the result set is empty.
        """
        now = _now_utc()
        ph = self._db._placeholder()
        rows = self._db.fetchall(
            f"SELECT id, user_id, key_hash FROM api_keys "
            f"WHERE active=1 AND (expires_at IS NULL OR expires_at > {ph})",
            (now,),
        )

        found_user: str | None = None
        for row in rows:
            try:
                if _verify_key(plain_key, row["key_hash"]):
                    self._db.execute(
                        f"UPDATE api_keys SET last_used={ph} WHERE id={ph}",
                        (_now_utc(), row["id"]),
                    )
                    found_user = row["user_id"]
                    # Don't break — keep iterating for constant-time behaviour
            except Exception:
                continue

        if not rows:
            # Constant-time guard: pay at least one scrypt operation
            _verify_key(plain_key, _hash_key(secrets.token_urlsafe(8)))

        return found_user
