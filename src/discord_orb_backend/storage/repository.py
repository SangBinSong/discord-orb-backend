"""SQLite-backed persistence repository for Discord Orb."""

from __future__ import annotations

import hashlib
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Self

from .db import open_database, resolve_db_path

ALLOWED_PLATFORMS: frozenset[str] = frozenset({"android", "macos", "windows"})


class StorageError(Exception):
    """Base exception for storage layer errors."""


class InvalidOrExpiredTicketError(StorageError):
    """Raised when an OAuth exchange ticket is missing, expired, or already consumed."""


class InvalidSessionError(StorageError):
    """Raised when a session or refresh token cannot be found."""


class SessionExpiredError(StorageError):
    """Raised when a session has passed its fixed expiration timestamp."""


class SessionRevokedError(StorageError):
    """Raised when attempting to use a revoked session."""


class RefreshTokenReusedError(StorageError):
    """Raised when a previously rotated refresh token is presented again."""


@dataclass(frozen=True, slots=True)
class OAuthTicketRecord:
    """Persisted single-use OAuth exchange ticket metadata."""

    ticket_hash: str
    discord_user_id: str
    guilds_json: str
    pkce_code_challenge: str
    redirect_uri: str
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """Persisted Flutter client session with refresh token rotation hashes."""

    session_id: str
    discord_user_id: str
    device_name: str
    device_id: str
    platform: str
    current_refresh_token_hash: str
    previous_refresh_token_hash: str | None
    created_at: datetime
    session_expires_at: datetime
    revoked_at: datetime | None = None


def hash_token(raw_value: str) -> str:
    """Return the SHA-256 hex digest of a raw secret token or ticket."""
    return hashlib.sha256(raw_value.encode("utf-8")).hexdigest()


def _resolve_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(UTC)
    if now.tzinfo is None:
        return now.replace(tzinfo=UTC)
    return now.astimezone(UTC)


def _format_dt(dt: datetime) -> str:
    return _resolve_now(dt).isoformat()


def _parse_dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _row_to_ticket(row: sqlite3.Row) -> OAuthTicketRecord:
    consumed_raw = row["consumed_at"]
    return OAuthTicketRecord(
        ticket_hash=row["ticket_hash"],
        discord_user_id=row["discord_user_id"],
        guilds_json=row["guilds_json"],
        pkce_code_challenge=row["pkce_code_challenge"],
        redirect_uri=row["redirect_uri"],
        created_at=_parse_dt(row["created_at"]),
        expires_at=_parse_dt(row["expires_at"]),
        consumed_at=_parse_dt(consumed_raw) if consumed_raw is not None else None,
    )


def _row_to_session(row: sqlite3.Row) -> SessionRecord:
    revoked_raw = row["revoked_at"]
    return SessionRecord(
        session_id=row["session_id"],
        discord_user_id=row["discord_user_id"],
        device_name=row["device_name"],
        device_id=row["device_id"],
        platform=row["platform"],
        current_refresh_token_hash=row["current_refresh_token_hash"],
        previous_refresh_token_hash=row["previous_refresh_token_hash"],
        created_at=_parse_dt(row["created_at"]),
        session_expires_at=_parse_dt(row["session_expires_at"]),
        revoked_at=_parse_dt(revoked_raw) if revoked_raw is not None else None,
    )


class OrbRepository:
    """Thread-safe SQLite repository for tickets, sessions, and bot state."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = resolve_db_path(db_path)
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = open_database(self._db_path)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _require_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise StorageError("Repository connection is closed")
        return self._conn

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def create_oauth_ticket(
        self,
        ticket: str,
        discord_user_id: str,
        guilds_json: str,
        pkce_code_challenge: str,
        redirect_uri: str,
        ttl_seconds: int = 120,
        now: datetime | None = None,
    ) -> OAuthTicketRecord:
        """Persist a hashed single-use OAuth exchange ticket."""
        if not ticket:
            raise ValueError("ticket must not be empty")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

        created_at = _resolve_now(now)
        expires_at = created_at + timedelta(seconds=ttl_seconds)
        ticket_hash = hash_token(ticket)

        with self._lock:
            conn = self._require_conn()
            with conn:
                conn.execute(
                    """
                    INSERT INTO oauth_tickets (
                        ticket_hash,
                        discord_user_id,
                        guilds_json,
                        pkce_code_challenge,
                        redirect_uri,
                        created_at,
                        expires_at,
                        consumed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        ticket_hash,
                        discord_user_id,
                        guilds_json,
                        pkce_code_challenge,
                        redirect_uri,
                        _format_dt(created_at),
                        _format_dt(expires_at),
                    ),
                )

        return OAuthTicketRecord(
            ticket_hash=ticket_hash,
            discord_user_id=discord_user_id,
            guilds_json=guilds_json,
            pkce_code_challenge=pkce_code_challenge,
            redirect_uri=redirect_uri,
            created_at=created_at,
            expires_at=expires_at,
            consumed_at=None,
        )

    def consume_oauth_ticket(
        self,
        ticket: str,
        now: datetime | None = None,
    ) -> OAuthTicketRecord:
        """Atomically consume an OAuth ticket once if valid and unexpired."""
        if not ticket:
            raise InvalidOrExpiredTicketError("OAuth ticket not found")

        current_time = _resolve_now(now)
        ticket_hash = hash_token(ticket)

        with self._lock:
            conn = self._require_conn()
            with conn:
                row = conn.execute(
                    "SELECT * FROM oauth_tickets WHERE ticket_hash = ?",
                    (ticket_hash,),
                ).fetchone()
                if row is None:
                    raise InvalidOrExpiredTicketError("OAuth ticket not found")

                record = _row_to_ticket(row)
                if record.consumed_at is not None:
                    raise InvalidOrExpiredTicketError("OAuth ticket already consumed")
                if record.expires_at <= current_time:
                    raise InvalidOrExpiredTicketError("OAuth ticket expired")

                cursor = conn.execute(
                    """
                    UPDATE oauth_tickets
                    SET consumed_at = ?
                    WHERE ticket_hash = ? AND consumed_at IS NULL
                    """,
                    (_format_dt(current_time), ticket_hash),
                )
                if cursor.rowcount != 1:
                    raise InvalidOrExpiredTicketError("OAuth ticket already consumed")

                updated_row = conn.execute(
                    "SELECT * FROM oauth_tickets WHERE ticket_hash = ?",
                    (ticket_hash,),
                ).fetchone()
                if updated_row is None:
                    raise InvalidOrExpiredTicketError("OAuth ticket not found")
                return _row_to_ticket(updated_row)

    def create_session(
        self,
        discord_user_id: str,
        device_name: str,
        device_id: str,
        platform: str,
        refresh_token: str,
        ttl_days: int = 30,
        now: datetime | None = None,
    ) -> SessionRecord:
        """Create a new Flutter session with a fixed expiration timestamp."""
        if platform not in ALLOWED_PLATFORMS:
            raise ValueError(f"Unsupported platform: {platform!r}")
        if not refresh_token:
            raise ValueError("refresh_token must not be empty")
        if ttl_days <= 0:
            raise ValueError("ttl_days must be positive")

        session_id = str(uuid.uuid4())
        created_at = _resolve_now(now)
        session_expires_at = created_at + timedelta(days=ttl_days)
        refresh_token_hash = hash_token(refresh_token)

        with self._lock:
            conn = self._require_conn()
            with conn:
                conn.execute(
                    """
                    INSERT INTO flutter_sessions (
                        session_id,
                        discord_user_id,
                        device_name,
                        device_id,
                        platform,
                        current_refresh_token_hash,
                        previous_refresh_token_hash,
                        created_at,
                        session_expires_at,
                        revoked_at
                    ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, NULL)
                    """,
                    (
                        session_id,
                        discord_user_id,
                        device_name,
                        device_id,
                        platform,
                        refresh_token_hash,
                        _format_dt(created_at),
                        _format_dt(session_expires_at),
                    ),
                )

        return SessionRecord(
            session_id=session_id,
            discord_user_id=discord_user_id,
            device_name=device_name,
            device_id=device_id,
            platform=platform,
            current_refresh_token_hash=refresh_token_hash,
            previous_refresh_token_hash=None,
            created_at=created_at,
            session_expires_at=session_expires_at,
            revoked_at=None,
        )

    def get_session(self, session_id: str) -> SessionRecord | None:
        """Fetch a session record by its UUID."""
        with self._lock:
            conn = self._require_conn()
            row = conn.execute(
                "SELECT * FROM flutter_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            return _row_to_session(row) if row is not None else None

    def is_session_active(
        self,
        session_id: str,
        now: datetime | None = None,
    ) -> bool:
        """Return whether the session exists, is not revoked, and has not expired."""
        current_time = _resolve_now(now)
        session = self.get_session(session_id)
        if session is None:
            return False
        if session.revoked_at is not None:
            return False
        return session.session_expires_at > current_time

    def rotate_refresh_token(
        self,
        presented_refresh_token: str,
        new_refresh_token: str,
        now: datetime | None = None,
    ) -> SessionRecord:
        """Rotate a valid refresh token or revoke the session on token reuse."""
        if not presented_refresh_token:
            raise InvalidSessionError("Invalid refresh token")
        if not new_refresh_token:
            raise ValueError("new_refresh_token must not be empty")

        current_time = _resolve_now(now)
        presented_hash = hash_token(presented_refresh_token)
        new_hash = hash_token(new_refresh_token)

        reused_detected = False
        with self._lock:
            conn = self._require_conn()
            with conn:
                current_row = conn.execute(
                    "SELECT * FROM flutter_sessions WHERE current_refresh_token_hash = ?",
                    (presented_hash,),
                ).fetchone()
                if current_row is not None:
                    session = _row_to_session(current_row)
                    if session.revoked_at is not None:
                        raise SessionRevokedError("Session has been revoked")
                    if session.session_expires_at <= current_time:
                        raise SessionExpiredError("Session has expired")

                    conn.execute(
                        """
                        UPDATE flutter_sessions
                        SET previous_refresh_token_hash = current_refresh_token_hash,
                            current_refresh_token_hash = ?
                        WHERE session_id = ?
                          AND current_refresh_token_hash = ?
                          AND revoked_at IS NULL
                        """,
                        (new_hash, session.session_id, presented_hash),
                    )
                    updated_row = conn.execute(
                        "SELECT * FROM flutter_sessions WHERE session_id = ?",
                        (session.session_id,),
                    ).fetchone()
                    if updated_row is None:
                        raise InvalidSessionError("Session not found after rotation")
                    return _row_to_session(updated_row)

                previous_row = conn.execute(
                    "SELECT * FROM flutter_sessions WHERE previous_refresh_token_hash = ?",
                    (presented_hash,),
                ).fetchone()
                if previous_row is not None:
                    if previous_row["revoked_at"] is None:
                        conn.execute(
                            """
                            UPDATE flutter_sessions
                            SET revoked_at = ?
                            WHERE session_id = ? AND revoked_at IS NULL
                            """,
                            (_format_dt(current_time), previous_row["session_id"]),
                        )
                    reused_detected = True

            if reused_detected:
                raise RefreshTokenReusedError("Refresh token reuse detected; session revoked")

            raise InvalidSessionError("Invalid refresh token")

    def revoke_session(
        self,
        session_id: str,
        now: datetime | None = None,
    ) -> bool:
        """Revoke an active session; returns True if it was newly revoked."""
        current_time = _resolve_now(now)
        with self._lock:
            conn = self._require_conn()
            with conn:
                cursor = conn.execute(
                    """
                    UPDATE flutter_sessions
                    SET revoked_at = ?
                    WHERE session_id = ? AND revoked_at IS NULL
                    """,
                    (_format_dt(current_time), session_id),
                )
                return cursor.rowcount > 0

    def list_active_sessions(
        self,
        now: datetime | None = None,
    ) -> list[SessionRecord]:
        """Return all unrevoked, unexpired sessions."""
        current_time = _resolve_now(now)
        with self._lock:
            conn = self._require_conn()
            rows = conn.execute(
                """
                SELECT * FROM flutter_sessions
                WHERE revoked_at IS NULL
                ORDER BY created_at ASC
                """
            ).fetchall()
            sessions = [_row_to_session(row) for row in rows]
            return [s for s in sessions if s.session_expires_at > current_time]

    def is_bot_enabled(self) -> bool:
        """Return persisted bot enabled flag (defaults to True)."""
        with self._lock:
            conn = self._require_conn()
            row = conn.execute("SELECT bot_enabled FROM instance_state WHERE id = 1").fetchone()
            if row is None:
                return True
            return bool(row["bot_enabled"])

    def set_bot_enabled(
        self,
        enabled: bool,
        now: datetime | None = None,
    ) -> bool:
        """Persist the bot enabled flag in instance_state."""
        current_time = _resolve_now(now)
        flag_value = 1 if enabled else 0
        with self._lock:
            conn = self._require_conn()
            with conn:
                conn.execute(
                    """
                    INSERT INTO instance_state (id, bot_enabled, updated_at)
                    VALUES (1, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        bot_enabled = excluded.bot_enabled,
                        updated_at = excluded.updated_at
                    """,
                    (flag_value, _format_dt(current_time)),
                )
        return bool(enabled)


Repository = OrbRepository
StorageRepository = OrbRepository
