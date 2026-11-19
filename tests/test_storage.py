"""Tests for the SQLite storage layer."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from discord_orb_backend.storage import (
    InvalidOrExpiredTicketError,
    InvalidSessionError,
    OrbRepository,
    RefreshTokenReusedError,
    Repository,
    SessionExpiredError,
    SessionRevokedError,
    StorageRepository,
    hash_token,
)


def test_sqlite_pragmas_schema_and_constructor_compatibility(tmp_path: Path) -> None:
    db_file = tmp_path / "nested" / "orb.db"

    assert Repository is OrbRepository
    assert StorageRepository is OrbRepository

    with OrbRepository(db_file) as repo:
        conn = repo._require_conn()
        journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        foreign_keys = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        busy_timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]

        assert str(journal_mode).lower() == "wal"
        assert foreign_keys == 1
        assert busy_timeout == 5000

        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert {"oauth_tickets", "flutter_sessions", "instance_state"} <= tables

    # Parameterless in-memory constructor also works and can be closed cleanly.
    mem_repo = OrbRepository()
    assert mem_repo.is_bot_enabled() is True
    mem_repo.close()
    mem_repo.close()


def test_oauth_ticket_create_and_single_use_consume(tmp_path: Path) -> None:
    db_file = tmp_path / "tickets.db"
    now = datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC)
    raw_ticket = "raw-oauth-ticket-value"

    with OrbRepository(db_file) as repo:
        created = repo.create_oauth_ticket(
            ticket=raw_ticket,
            discord_user_id="user-123",
            guilds_json='[{"id": "g1", "name": "Orb Guild"}]',
            pkce_code_challenge="challenge-abc",
            redirect_uri="discordorb://callback",
            ttl_seconds=120,
            now=now,
        )

        assert created.ticket_hash == hash_token(raw_ticket)
        assert created.ticket_hash != raw_ticket
        assert created.expires_at == now + timedelta(seconds=120)
        assert created.consumed_at is None

        # Ensure plaintext ticket is not stored anywhere in the DB row.
        row = (
            repo._require_conn()
            .execute(
                "SELECT * FROM oauth_tickets WHERE ticket_hash = ?",
                (created.ticket_hash,),
            )
            .fetchone()
        )
        assert row is not None
        assert raw_ticket not in tuple(row)

        consumed = repo.consume_oauth_ticket(raw_ticket, now=now + timedelta(seconds=30))
        assert consumed.ticket_hash == created.ticket_hash
        assert consumed.discord_user_id == "user-123"
        assert consumed.consumed_at == now + timedelta(seconds=30)

        with pytest.raises(InvalidOrExpiredTicketError):
            repo.consume_oauth_ticket(raw_ticket, now=now + timedelta(seconds=31))


def test_oauth_ticket_expired_and_missing_raise(tmp_path: Path) -> None:
    db_file = tmp_path / "tickets_exp.db"
    now = datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC)

    with OrbRepository(db_file) as repo:
        repo.create_oauth_ticket(
            ticket="expiring-ticket",
            discord_user_id="user-123",
            guilds_json="[]",
            pkce_code_challenge="challenge-xyz",
            redirect_uri="discordorb://callback",
            ttl_seconds=120,
            now=now,
        )

        with pytest.raises(InvalidOrExpiredTicketError):
            repo.consume_oauth_ticket("expiring-ticket", now=now + timedelta(seconds=120))

        with pytest.raises(InvalidOrExpiredTicketError):
            repo.consume_oauth_ticket("does-not-exist", now=now)

        with pytest.raises(InvalidOrExpiredTicketError):
            repo.consume_oauth_ticket("", now=now)


def test_oauth_ticket_concurrent_consume_is_atomic(tmp_path: Path) -> None:
    db_file = tmp_path / "tickets_concurrent.db"
    now = datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC)

    with OrbRepository(db_file) as repo:
        repo.create_oauth_ticket(
            ticket="race-ticket",
            discord_user_id="user-999",
            guilds_json="[]",
            pkce_code_challenge="challenge-race",
            redirect_uri="discordorb://callback",
            ttl_seconds=120,
            now=now,
        )

        def _attempt() -> bool:
            try:
                repo.consume_oauth_ticket("race-ticket", now=now + timedelta(seconds=1))
                return True
            except InvalidOrExpiredTicketError:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: _attempt(), range(8)))

        assert results.count(True) == 1
        assert results.count(False) == 7


def test_session_lifecycle_and_refresh_token_rotation(tmp_path: Path) -> None:
    db_file = tmp_path / "sessions.db"
    t0 = datetime(2026, 11, 19, 10, 0, 0, tzinfo=UTC)
    refresh_1 = "refresh-token-1"
    refresh_2 = "refresh-token-2"
    refresh_3 = "refresh-token-3"

    with OrbRepository(db_file) as repo:
        session = repo.create_session(
            discord_user_id="user-1",
            device_name="MacBook Pro",
            device_id="dev-mac-01",
            platform="macos",
            refresh_token=refresh_1,
            ttl_days=30,
            now=t0,
        )

        assert session.session_expires_at == t0 + timedelta(days=30)
        assert session.current_refresh_token_hash == hash_token(refresh_1)
        assert session.previous_refresh_token_hash is None
        assert session.revoked_at is None
        assert repo.is_session_active(session.session_id, now=t0) is True
        assert repo.get_session(session.session_id) == session

        # Ensure plaintext refresh token is never stored in SQLite.
        row = (
            repo._require_conn()
            .execute(
                "SELECT * FROM flutter_sessions WHERE session_id = ?",
                (session.session_id,),
            )
            .fetchone()
        )
        assert row is not None
        assert refresh_1 not in tuple(row)

        # Rotate after 5 days; session_expires_at must remain fixed at t0 + 30 days.
        t1 = t0 + timedelta(days=5)
        rotated = repo.rotate_refresh_token(refresh_1, refresh_2, now=t1)
        assert rotated.session_id == session.session_id
        assert rotated.current_refresh_token_hash == hash_token(refresh_2)
        assert rotated.previous_refresh_token_hash == hash_token(refresh_1)
        assert rotated.session_expires_at == t0 + timedelta(days=30)
        assert rotated.revoked_at is None

        # Reuse of previous refresh token must revoke the session and raise.
        t2 = t0 + timedelta(days=6)
        with pytest.raises(RefreshTokenReusedError):
            repo.rotate_refresh_token(refresh_1, refresh_3, now=t2)

        assert repo.is_session_active(session.session_id, now=t2) is False
        revoked_session = repo.get_session(session.session_id)
        assert revoked_session is not None
        assert revoked_session.revoked_at == t2

        # Even the latest current token cannot be used once the session is revoked.
        with pytest.raises(SessionRevokedError):
            repo.rotate_refresh_token(refresh_2, refresh_3, now=t2 + timedelta(seconds=1))


def test_session_expiration_revocation_listing_and_platform_checks(tmp_path: Path) -> None:
    db_file = tmp_path / "sessions_more.db"
    t0 = datetime(2026, 11, 19, 10, 0, 0, tzinfo=UTC)

    with OrbRepository(db_file) as repo:
        with pytest.raises(ValueError):
            repo.create_session(
                discord_user_id="u1",
                device_name="Linux Box",
                device_id="dev-lin",
                platform="linux",
                refresh_token="rt-bad",
                now=t0,
            )

        # Also verify SQLite CHECK constraint directly.
        with pytest.raises(sqlite3.IntegrityError):
            repo._require_conn().execute(
                """
                INSERT INTO flutter_sessions (
                    session_id, discord_user_id, device_name, device_id,
                    platform, current_refresh_token_hash, created_at, session_expires_at
                ) VALUES ('sid-bad', 'u1', 'Box', 'd1', 'linux', 'h1', ?, ?)
                """,
                (t0.isoformat(), (t0 + timedelta(days=30)).isoformat()),
            )

        s_active = repo.create_session(
            discord_user_id="u1",
            device_name="Pixel",
            device_id="dev-and",
            platform="android",
            refresh_token="rt-active",
            ttl_days=30,
            now=t0,
        )
        s_revoked = repo.create_session(
            discord_user_id="u1",
            device_name="Surface",
            device_id="dev-win",
            platform="windows",
            refresh_token="rt-revoked",
            ttl_days=30,
            now=t0 + timedelta(minutes=1),
        )
        s_short = repo.create_session(
            discord_user_id="u2",
            device_name="Mac",
            device_id="dev-mac",
            platform="macos",
            refresh_token="rt-short",
            ttl_days=1,
            now=t0 + timedelta(minutes=2),
        )

        assert repo.revoke_session(s_revoked.session_id, now=t0 + timedelta(minutes=5)) is True
        assert repo.revoke_session(s_revoked.session_id, now=t0 + timedelta(minutes=6)) is False
        assert repo.revoke_session("non-existent-id", now=t0) is False

        # At t0 + 2 days, s_short is expired and s_revoked is revoked; only s_active remains.
        t_check = t0 + timedelta(days=2)
        active = repo.list_active_sessions(now=t_check)
        assert [s.session_id for s in active] == [s_active.session_id]
        assert repo.is_session_active(s_short.session_id, now=t_check) is False
        assert repo.is_session_active("missing-id", now=t_check) is False

        with pytest.raises(SessionExpiredError):
            repo.rotate_refresh_token("rt-short", "rt-short-new", now=t_check)

        with pytest.raises(InvalidSessionError):
            repo.rotate_refresh_token("unknown-refresh-token", "rt-new", now=t_check)


def test_bot_state_persists_across_restarts(tmp_path: Path) -> None:
    db_file = tmp_path / "bot_state.db"
    t0 = datetime(2026, 11, 19, 10, 0, 0, tzinfo=UTC)

    repo1 = OrbRepository(db_file)
    try:
        assert repo1.is_bot_enabled() is True
        assert repo1.set_bot_enabled(False, now=t0) is False
        assert repo1.is_bot_enabled() is False
    finally:
        repo1.close()

    repo2 = OrbRepository(db_file)
    try:
        assert repo2.is_bot_enabled() is False
        assert repo2.set_bot_enabled(True, now=t0 + timedelta(minutes=1)) is True
        assert repo2.is_bot_enabled() is True
    finally:
        repo2.close()

    repo3 = OrbRepository(db_file)
    try:
        assert repo3.is_bot_enabled() is True
    finally:
        repo3.close()
