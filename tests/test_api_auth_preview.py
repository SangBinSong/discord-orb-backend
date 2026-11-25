"""Tests for RFC 8252 auth flow, token rotation, channel discovery, and preview API."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

from discord_orb_backend.api.tokens import (
    InvalidTokenError,
    TokenExpiredError,
    create_access_token,
    create_oauth_state_token,
    verify_access_token,
    verify_oauth_state_token,
    verify_pkce_s256,
)
from discord_orb_backend.config import Settings
from discord_orb_backend.discord import (
    REQUIRED_PERMISSIONS,
    VIEW_CHANNEL,
    DiscordClient,
)
from discord_orb_backend.main import create_app
from discord_orb_backend.storage import OrbRepository

TEST_SECRET = "test-orb-session-secret-0123456789"


def _make_pkce(verifier: str = "verifier-" + ("a" * 40)) -> tuple[str, str]:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _make_settings(
    tmp_path: Path,
    *,
    bot_token: str = "test-bot-token",
    public_url: str = "https://orb.example.com",
) -> Settings:
    return Settings(
        orb_public_url=public_url,
        orb_db_path=str(tmp_path / "orb.db"),
        orb_discord_client_id="test-client-id",
        orb_discord_client_secret="test-client-secret",
        orb_discord_bot_token=bot_token,
        orb_operator_discord_ids=("op-1",),
        orb_session_secret=TEST_SECRET,
    )


def _build_discord_mock(
    *,
    oauth_user_id: str = "user-1",
    oauth_guilds: list[dict[str, str]] | None = None,
    bot_guilds: list[dict[str, str]] | None = None,
    channels_by_guild: dict[str, list[dict[str, object]]] | None = None,
    perms_by_channel_user: dict[tuple[str, str], int | None] | None = None,
    messages_by_channel: dict[str, list[dict[str, object]]] | None = None,
    rate_limit_path: str | None = None,
    on_messages_fetch: object | None = None,
    calls_log: list[str] | None = None,
) -> httpx.MockTransport:
    resolved_oauth_guilds = (
        oauth_guilds if oauth_guilds is not None else [{"id": "g-1", "name": "Guild One"}]
    )
    resolved_bot_guilds = (
        bot_guilds if bot_guilds is not None else [{"id": "g-1", "name": "Guild One"}]
    )
    resolved_channels = (
        channels_by_guild
        if channels_by_guild is not None
        else {
            "g-1": [{"id": "ch-1", "guild_id": "g-1", "name": "general", "type": 0, "nsfw": False}]
        }
    )
    resolved_perms = (
        perms_by_channel_user
        if perms_by_channel_user is not None
        else {
            ("ch-1", "bot-1"): REQUIRED_PERMISSIONS,
            ("ch-1", "user-1"): REQUIRED_PERMISSIONS,
        }
    )
    resolved_messages = (
        messages_by_channel
        if messages_by_channel is not None
        else {
            "ch-1": [
                {
                    "id": f"msg-{i}",
                    "author": {"username": f"user{i}", "global_name": f"User {i}"},
                    "timestamp": f"2026-11-19T12:00:0{i}+00:00",
                    "content": f"message {i}",
                }
                for i in range(12)
            ]
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if calls_log is not None:
            calls_log.append(f"{request.method} {path}")

        if rate_limit_path is not None and path == rate_limit_path:
            return httpx.Response(
                429,
                headers={"Retry-After": "4.2"},
                json={"retry_after": 4.2},
            )

        if path == "/api/v10/oauth2/token":
            return httpx.Response(200, json={"access_token": "ephemeral-discord-oauth-token"})

        if path == "/api/v10/users/@me":
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bot "):
                return httpx.Response(200, json={"id": "bot-1", "username": "orb-bot"})
            return httpx.Response(
                200,
                json={"id": oauth_user_id, "username": "alice", "global_name": "Alice"},
            )

        if path == "/api/v10/users/@me/guilds":
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bot "):
                return httpx.Response(200, json=resolved_bot_guilds)
            return httpx.Response(200, json=resolved_oauth_guilds)

        if path.startswith("/api/v10/guilds/") and path.endswith("/channels"):
            guild_id = path.split("/")[4]
            if guild_id not in resolved_channels:
                return httpx.Response(404, json={"message": "Unknown Guild"})
            return httpx.Response(200, json=resolved_channels[guild_id])

        if "/permissions/member/" in path:
            parts = path.split("/")
            channel_id = parts[4]
            user_id = parts[7]
            perm = resolved_perms.get((channel_id, user_id))
            if perm is None:
                return httpx.Response(404, json={"message": "Unknown Member"})
            return httpx.Response(200, json={"permissions": str(perm)})

        if path.startswith("/api/v10/channels/") and path.endswith("/messages"):
            channel_id = path.split("/")[4]
            if callable(on_messages_fetch):
                on_messages_fetch()
            return httpx.Response(200, json=resolved_messages.get(channel_id, []))

        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _complete_oauth_login(
    client: TestClient,
    *,
    redirect_uri: str = "http://127.0.0.1:43210/callback",
    verifier: str = "verifier-" + ("x" * 40),
    client_state: str = "client-csrf-state-123",
    device_name: str = "MacBook Pro",
    device_id: str = "dev-mac-1",
    platform: str = "macos",
) -> dict[str, str]:
    _, challenge = _make_pkce(verifier)
    login_resp = client.get(
        "/auth/discord/login",
        params={
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": client_state,
        },
        follow_redirects=False,
    )
    assert login_resp.status_code == 302
    discord_location = urlparse(login_resp.headers["location"])
    server_state = parse_qs(discord_location.query)["state"][0]

    callback_resp = client.get(
        "/auth/discord/callback",
        params={"code": "discord-auth-code", "state": server_state},
        follow_redirects=False,
    )
    assert callback_resp.status_code == 302
    app_redirect = callback_resp.headers["location"]
    assert "access_token" not in app_redirect
    assert "refresh_token" not in app_redirect

    parsed_app = urlparse(app_redirect)
    query = parse_qs(parsed_app.query)
    assert query["state"][0] == client_state
    ticket = query["ticket"][0]

    exchange_resp = client.post(
        "/api/v1/auth/exchange",
        json={
            "ticket": ticket,
            "code_verifier": verifier,
            "device_name": device_name,
            "device_id": device_id,
            "platform": platform,
        },
    )
    assert exchange_resp.status_code == 200
    return exchange_resp.json()


def test_token_signing_verification_expiration_and_pkce() -> None:
    t0 = datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC)
    token, expires_at = create_access_token("sess-1", "user-1", TEST_SECRET, now=t0)
    assert expires_at == t0 + timedelta(minutes=15)

    claims = verify_access_token(token, TEST_SECRET, now=t0 + timedelta(minutes=14))
    assert claims.session_id == "sess-1"
    assert claims.discord_user_id == "user-1"
    assert claims.typ == "flutter_access"

    with pytest.raises(TokenExpiredError):
        verify_access_token(token, TEST_SECRET, now=t0 + timedelta(minutes=15))

    with pytest.raises(InvalidTokenError):
        verify_access_token(token + "tamper", TEST_SECRET, now=t0)

    with pytest.raises(InvalidTokenError):
        verify_access_token(token, "wrong-secret", now=t0)

    # OAuth state tokens must never verify as Flutter access tokens.
    state_token = create_oauth_state_token(
        "discordorb://auth/callback",
        "challenge-1",
        "client-state-1",
        TEST_SECRET,
        now=t0,
    )
    state_claims = verify_oauth_state_token(state_token, TEST_SECRET, now=t0)
    assert state_claims.redirect_uri == "discordorb://auth/callback"
    assert state_claims.code_challenge == "challenge-1"
    assert state_claims.client_state == "client-state-1"

    with pytest.raises(InvalidTokenError):
        verify_access_token(state_token, TEST_SECRET, now=t0)

    with pytest.raises(TokenExpiredError):
        verify_oauth_state_token(state_token, TEST_SECRET, now=t0 + timedelta(minutes=10))

    verifier, challenge = _make_pkce("sample-verifier-" + ("k" * 32))
    assert verify_pkce_s256(verifier, challenge) is True
    assert verify_pkce_s256("wrong-verifier", challenge) is False
    assert verify_pkce_s256("", challenge) is False
    assert verify_pkce_s256(verifier, "") is False


def test_login_validates_rfc8252_redirect_uri_and_pkce_params(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    repo = OrbRepository(settings.orb_db_path)
    discord_client = DiscordClient(settings, transport=_build_discord_mock())
    app = create_app(settings, repository=repo, discord_client=discord_client)

    _, challenge = _make_pkce()

    with TestClient(app) as client:
        for valid_uri in (
            "http://127.0.0.1:1/callback",
            "http://127.0.0.1:54321/callback",
            "http://127.0.0.1:65535/callback",
            "discordorb://auth/callback",
        ):
            resp = client.get(
                "/auth/discord/login",
                params={
                    "redirect_uri": valid_uri,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "state-1",
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302
            parsed = urlparse(resp.headers["location"])
            assert parsed.scheme == "https"
            assert parsed.netloc == "discord.com"
            assert parsed.path == "/oauth2/authorize"
            qs = parse_qs(parsed.query)
            assert qs["scope"] == ["identify guilds"]
            assert qs["redirect_uri"] == ["https://orb.example.com/auth/discord/callback"]
            assert qs["client_id"] == ["test-client-id"]

        for bad_uri in (
            "http://127.0.0.1/callback",
            "http://127.0.0.1:0/callback",
            "http://127.0.0.1:65536/callback",
            "http://127.0.0.1:8080/callback?foo=bar",
            "http://127.0.0.1:8080/callback#frag",
            "http://127.0.0.1:8080/other",
            "http://localhost:8080/callback",
            "https://evil.example.com/callback",
            "discordorb://auth/callback?x=1",
            "discordorb://auth/callback#frag",
            "discordorb://other/callback",
        ):
            resp = client.get(
                "/auth/discord/login",
                params={
                    "redirect_uri": bad_uri,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "state-1",
                },
                follow_redirects=False,
            )
            assert resp.status_code == 400, f"Expected 400 for {bad_uri}"

        # Reject non-S256 code_challenge_method
        bad_method = client.get(
            "/auth/discord/login",
            params={
                "redirect_uri": "discordorb://auth/callback",
                "code_challenge": challenge,
                "code_challenge_method": "plain",
                "state": "state-1",
            },
            follow_redirects=False,
        )
        assert bad_method.status_code == 400

        # Reject missing code_challenge / state
        missing_state = client.get(
            "/auth/discord/login",
            params={
                "redirect_uri": "discordorb://auth/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert missing_state.status_code == 400

    repo.close()


def test_callback_exchange_pkce_single_use_and_android_redirect(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    repo = OrbRepository(settings.orb_db_path)
    discord_client = DiscordClient(settings, transport=_build_discord_mock())
    app = create_app(settings, repository=repo, discord_client=discord_client)

    verifier, challenge = _make_pkce("android-verifier-" + ("z" * 40))

    with TestClient(app) as client:
        # Invalid state rejected at callback
        bad_cb = client.get(
            "/auth/discord/callback",
            params={"code": "abc", "state": "tampered"},
            follow_redirects=False,
        )
        assert bad_cb.status_code == 400

        login_resp = client.get(
            "/auth/discord/login",
            params={
                "redirect_uri": "discordorb://auth/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "android-state-99",
            },
            follow_redirects=False,
        )
        assert login_resp.status_code == 302
        server_state = parse_qs(urlparse(login_resp.headers["location"]).query)["state"][0]

        # OAuth error propagates safely without minting ticket
        denied_cb = client.get(
            "/auth/discord/callback",
            params={"error": "access_denied", "state": server_state},
            follow_redirects=False,
        )
        assert denied_cb.status_code == 302
        assert denied_cb.headers["location"].startswith("discordorb://auth/callback?")
        denied_qs = parse_qs(urlparse(denied_cb.headers["location"]).query)
        assert denied_qs == {"error": ["access_denied"], "state": ["android-state-99"]}

        # Successful callback mints ticket and omits tokens from URL
        ok_cb = client.get(
            "/auth/discord/callback",
            params={"code": "code-ok", "state": server_state},
            follow_redirects=False,
        )
        assert ok_cb.status_code == 302
        redirect_url = ok_cb.headers["location"]
        assert redirect_url.startswith("discordorb://auth/callback?")
        assert "access_token" not in redirect_url
        assert "refresh_token" not in redirect_url
        ok_qs = parse_qs(urlparse(redirect_url).query)
        assert ok_qs["state"] == ["android-state-99"]
        ticket = ok_qs["ticket"][0]

        # Wrong PKCE verifier fails AND burns the single-use ticket
        bad_pkce = client.post(
            "/api/v1/auth/exchange",
            json={
                "ticket": ticket,
                "code_verifier": "wrong-verifier",
                "device_name": "Pixel 9",
                "device_id": "dev-android-1",
                "platform": "android",
            },
        )
        assert bad_pkce.status_code == 400
        assert bad_pkce.json()["code"] == "invalid_pkce"

        reused_after_fail = client.post(
            "/api/v1/auth/exchange",
            json={
                "ticket": ticket,
                "code_verifier": verifier,
                "device_name": "Pixel 9",
                "device_id": "dev-android-1",
                "platform": "android",
            },
        )
        assert reused_after_fail.status_code == 400
        assert reused_after_fail.json()["code"] == "invalid_ticket"

        # Fresh ticket exchange succeeds once, second attempt fails
        tokens = _complete_oauth_login(
            client,
            redirect_uri="discordorb://auth/callback",
            verifier=verifier,
            client_state="android-state-100",
            device_name="Pixel 9",
            device_id="dev-android-1",
            platform="android",
        )
        assert set(tokens.keys()) == {
            "access_token",
            "refresh_token",
            "access_expires_at",
            "session_expires_at",
        }
        access_exp = datetime.fromisoformat(tokens["access_expires_at"])
        session_exp = datetime.fromisoformat(tokens["session_expires_at"])
        assert timedelta(minutes=14) < (access_exp - datetime.now(UTC)) <= timedelta(minutes=15)
        assert timedelta(days=29) < (session_exp - datetime.now(UTC)) <= timedelta(days=30)

    repo.close()


def test_refresh_rotation_reuse_detection_expiration_and_logout(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    repo = OrbRepository(settings.orb_db_path)
    discord_client = DiscordClient(settings, transport=_build_discord_mock())
    app = create_app(settings, repository=repo, discord_client=discord_client)

    with TestClient(app) as client:
        tokens_1 = _complete_oauth_login(client)
        rt1 = tokens_1["refresh_token"]
        session_exp_1 = tokens_1["session_expires_at"]

        # Valid refresh rotates token and preserves fixed session_expires_at
        refresh_resp = client.post("/api/v1/auth/refresh", json={"refresh_token": rt1})
        assert refresh_resp.status_code == 200
        tokens_2 = refresh_resp.json()
        rt2 = tokens_2["refresh_token"]
        assert rt2 != rt1
        assert tokens_2["session_expires_at"] == session_exp_1

        # Reusing old refresh token triggers 401 token_reused and revokes the session
        reuse_resp = client.post("/api/v1/auth/refresh", json={"refresh_token": rt1})
        assert reuse_resp.status_code == 401
        assert reuse_resp.json()["code"] == "token_reused"

        # Even the latest refresh token is now rejected as session_revoked
        revoked_resp = client.post("/api/v1/auth/refresh", json={"refresh_token": rt2})
        assert revoked_resp.status_code == 401
        assert revoked_resp.json()["code"] == "session_revoked"

        # Unknown refresh token -> 401 session_revoked
        unknown_resp = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "never-existed-token"},
        )
        assert unknown_resp.status_code == 401
        assert unknown_resp.json()["code"] == "session_revoked"

        # Expired session -> 401 session_expired
        past_t0 = datetime.now(UTC) - timedelta(days=31)
        expired_session = repo.create_session(
            discord_user_id="user-1",
            device_name="Win Box",
            device_id="dev-win-1",
            platform="windows",
            refresh_token="rt-expired",
            ttl_days=30,
            now=past_t0,
        )
        exp_resp = client.post("/api/v1/auth/refresh", json={"refresh_token": "rt-expired"})
        assert exp_resp.status_code == 401
        assert exp_resp.json()["code"] == "session_expired"
        assert repo.is_session_active(expired_session.session_id) is False

        # Logout via Bearer access token (no body)
        tokens_a = _complete_oauth_login(client, client_state="s-a")
        logout_a = client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {tokens_a['access_token']}"},
        )
        assert logout_a.status_code == 200
        assert logout_a.json() == {"revoked": True}
        assert (
            client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": tokens_a["refresh_token"]},
            ).status_code
            == 401
        )

        # Logout via refresh_token in body (e.g., when access token already expired)
        tokens_b = _complete_oauth_login(client, client_state="s-b")
        expired_at, _ = create_access_token(
            verify_access_token(tokens_b["access_token"], TEST_SECRET).session_id,
            "user-1",
            TEST_SECRET,
            now=datetime.now(UTC) - timedelta(minutes=20),
        )
        logout_b = client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {expired_at}"},
            json={"refresh_token": tokens_b["refresh_token"]},
        )
        assert logout_b.status_code == 200
        assert logout_b.json() == {"revoked": True}
        assert (
            client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": tokens_b["refresh_token"]},
            ).status_code
            == 401
        )

        # Logout without credentials -> 401
        assert client.post("/api/v1/auth/logout").status_code == 401

    repo.close()


def test_channels_filters_permissions_and_hides_denied_channels_and_guilds(
    tmp_path: Path,
) -> None:
    settings = _make_settings(tmp_path)
    repo = OrbRepository(settings.orb_db_path)

    channels_by_guild = {
        "g-shared": [
            {"id": "ch-ok", "guild_id": "g-shared", "name": "general", "type": 0, "nsfw": False},
            {
                "id": "ch-secret",
                "guild_id": "g-shared",
                "name": "mods-only",
                "type": 0,
                "nsfw": False,
            },
            {
                "id": "ch-bot-no-hist",
                "guild_id": "g-shared",
                "name": "bot-blind",
                "type": 0,
                "nsfw": False,
            },
            {"id": "ch-nsfw", "guild_id": "g-shared", "name": "nsfw", "type": 0, "nsfw": True},
            {"id": "ch-voice", "guild_id": "g-shared", "name": "voice", "type": 2, "nsfw": False},
        ],
        "g-other-user-only": [
            {
                "id": "ch-other",
                "guild_id": "g-other-user-only",
                "name": "private-guild-room",
                "type": 0,
                "nsfw": False,
            }
        ],
    }
    perms = {
        ("ch-ok", "bot-1"): REQUIRED_PERMISSIONS,
        ("ch-ok", "user-1"): REQUIRED_PERMISSIONS,
        ("ch-secret", "bot-1"): REQUIRED_PERMISSIONS,
        ("ch-secret", "user-1"): VIEW_CHANNEL,  # Missing READ_MESSAGE_HISTORY
        ("ch-secret", "user-2"): REQUIRED_PERMISSIONS,
        ("ch-bot-no-hist", "bot-1"): VIEW_CHANNEL,
        ("ch-bot-no-hist", "user-1"): REQUIRED_PERMISSIONS,
        ("ch-other", "bot-1"): REQUIRED_PERMISSIONS,
        ("ch-other", "user-2"): REQUIRED_PERMISSIONS,
        # user-1 is not in g-other-user-only -> None
    }
    calls_log: list[str] = []
    discord_client = DiscordClient(
        settings,
        transport=_build_discord_mock(
            oauth_user_id="user-1",
            bot_guilds=[
                {"id": "g-shared", "name": "Shared Guild"},
                {"id": "g-other-user-only", "name": "Secret Other Guild"},
            ],
            channels_by_guild=channels_by_guild,
            perms_by_channel_user=perms,
            calls_log=calls_log,
        ),
    )
    app = create_app(settings, repository=repo, discord_client=discord_client)

    with TestClient(app) as client:
        tokens = _complete_oauth_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        resp = client.get("/api/v1/channels", headers=headers)
        assert resp.status_code == 200
        assert resp.json() == {
            "guilds": [
                {
                    "guild_id": "g-shared",
                    "guild_name": "Shared Guild",
                    "guild_icon_url": None,
                    "channels": [
                        {
                            "guild_id": "g-shared",
                            "guild_name": "Shared Guild",
                            "guild_icon_url": None,
                            "channel_id": "ch-ok",
                            "channel_name": "general",
                        }
                    ],
                }
            ]
        }
        assert "mods-only" not in resp.text
        assert "Secret Other Guild" not in resp.text
        assert "private-guild-room" not in resp.text

        # Non-flutter token (e.g., oauth_login_state or operator token) must be rejected
        state_tok = create_oauth_state_token("discordorb://auth/callback", "ch", "st", TEST_SECRET)
        assert (
            client.get(
                "/api/v1/channels",
                headers={"Authorization": f"Bearer {state_tok}"},
            ).status_code
            == 401
        )

        # Disabling bot blocks /channels with 503 bot_unavailable without calling Discord
        calls_before = len(calls_log)
        repo.set_bot_enabled(False)
        disabled_resp = client.get("/api/v1/channels", headers=headers)
        assert disabled_resp.status_code == 503
        assert disabled_resp.json()["code"] == "bot_unavailable"
        assert len(calls_log) == calls_before

        # Revoking session blocks /channels with 401 session_revoked
        repo.set_bot_enabled(True)
        claims = verify_access_token(tokens["access_token"], TEST_SECRET)
        repo.revoke_session(claims.session_id)
        revoked_resp = client.get("/api/v1/channels", headers=headers)
        assert revoked_resp.status_code == 401
        assert revoked_resp.json()["code"] == "session_revoked"

    repo.close()


def test_messages_preview_permissions_rate_limit_and_bot_unconfigured(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    repo = OrbRepository(settings.orb_db_path)

    channels_by_guild = {
        "g-1": [
            {"id": "ch-ok", "guild_id": "g-1", "name": "general", "type": 0, "nsfw": False},
            {"id": "ch-denied", "guild_id": "g-1", "name": "locked", "type": 0, "nsfw": False},
            {"id": "ch-bot-bad", "guild_id": "g-1", "name": "no-bot", "type": 0, "nsfw": False},
            {"id": "ch-429", "guild_id": "g-1", "name": "busy", "type": 0, "nsfw": False},
        ]
    }
    perms = {
        ("ch-ok", "bot-1"): REQUIRED_PERMISSIONS,
        ("ch-ok", "user-1"): REQUIRED_PERMISSIONS,
        ("ch-denied", "bot-1"): REQUIRED_PERMISSIONS,
        ("ch-denied", "user-1"): VIEW_CHANNEL,
        ("ch-bot-bad", "bot-1"): VIEW_CHANNEL,
        ("ch-bot-bad", "user-1"): REQUIRED_PERMISSIONS,
        ("ch-429", "bot-1"): REQUIRED_PERMISSIONS,
        ("ch-429", "user-1"): REQUIRED_PERMISSIONS,
    }
    discord_client = DiscordClient(
        settings,
        transport=_build_discord_mock(
            channels_by_guild=channels_by_guild,
            perms_by_channel_user=perms,
            messages_by_channel={
                "ch-ok": [
                    {
                        "id": f"m-{i}",
                        "author": {"username": f"u{i}", "global_name": f"User {i}"},
                        "timestamp": f"2026-11-19T12:00:0{i}+00:00",
                        "content": f"body {i}",
                    }
                    for i in range(12)
                ]
            },
            rate_limit_path="/api/v10/channels/ch-429/messages",
        ),
    )
    app = create_app(settings, repository=repo, discord_client=discord_client)

    with TestClient(app) as client:
        tokens = _complete_oauth_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        ok_resp = client.get("/api/v1/guilds/g-1/channels/ch-ok/messages", headers=headers)
        assert ok_resp.status_code == 200
        body = ok_resp.json()
        assert body["guild_id"] == "g-1"
        assert body["channel_id"] == "ch-ok"
        assert len(body["messages"]) == 10
        assert body["messages"][0] == {
            "id": "m-0",
            "author_name": "User 0",
            "author_avatar_url": None,
            "timestamp": "2026-11-19T12:00:00+00:00",
            "content": "body 0",
        }

        denied_resp = client.get(
            "/api/v1/guilds/g-1/channels/ch-denied/messages",
            headers=headers,
        )
        assert denied_resp.status_code == 403
        assert denied_resp.json()["code"] == "access_denied"

        bot_bad_resp = client.get(
            "/api/v1/guilds/g-1/channels/ch-bot-bad/messages",
            headers=headers,
        )
        assert bot_bad_resp.status_code == 503
        assert bot_bad_resp.json()["code"] == "bot_unavailable"

        rl_resp = client.get("/api/v1/guilds/g-1/channels/ch-429/messages", headers=headers)
        assert rl_resp.status_code == 429
        assert rl_resp.json()["code"] == "rate_limited"
        assert rl_resp.headers["Retry-After"] == "5"

    repo.close()

    # Bot token unconfigured -> 503 bot_unavailable on both /channels and /messages
    no_bot_settings = _make_settings(tmp_path, bot_token="")
    no_bot_repo = OrbRepository(no_bot_settings.orb_db_path)
    no_bot_discord = DiscordClient(no_bot_settings, transport=_build_discord_mock())
    no_bot_app = create_app(no_bot_settings, repository=no_bot_repo, discord_client=no_bot_discord)
    with TestClient(no_bot_app) as client:
        tokens = _complete_oauth_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        assert client.get("/api/v1/channels", headers=headers).status_code == 503
        msg_resp = client.get("/api/v1/guilds/g-1/channels/ch-1/messages", headers=headers)
        assert msg_resp.status_code == 503
        assert msg_resp.json()["code"] == "bot_unavailable"
    no_bot_repo.close()


def test_messages_discards_payload_on_in_flight_revocation_or_bot_disable(
    tmp_path: Path,
) -> None:
    settings = _make_settings(tmp_path)
    repo = OrbRepository(settings.orb_db_path)

    state = {"action": "none", "session_id": ""}

    def on_messages_fetch() -> None:
        if state["action"] == "revoke":
            repo.revoke_session(state["session_id"])
        elif state["action"] == "disable_bot":
            repo.set_bot_enabled(False)

    discord_client = DiscordClient(
        settings,
        transport=_build_discord_mock(
            messages_by_channel={
                "ch-1": [
                    {
                        "id": "secret-msg-1",
                        "author": {"username": "alice"},
                        "timestamp": "2026-11-19T12:00:00+00:00",
                        "content": "TOP_SECRET_MESSAGE_BODY",
                    }
                ]
            },
            on_messages_fetch=on_messages_fetch,
        ),
    )
    app = create_app(settings, repository=repo, discord_client=discord_client)

    with TestClient(app) as client:
        # 1) Session revoked while Discord fetch is in flight -> 401, zero message content
        tokens_1 = _complete_oauth_login(client, client_state="inflight-1")
        state["session_id"] = verify_access_token(tokens_1["access_token"], TEST_SECRET).session_id
        state["action"] = "revoke"

        revoked_resp = client.get(
            "/api/v1/guilds/g-1/channels/ch-1/messages",
            headers={"Authorization": f"Bearer {tokens_1['access_token']}"},
        )
        assert revoked_resp.status_code == 401
        assert revoked_resp.json()["code"] == "session_revoked"
        assert "TOP_SECRET_MESSAGE_BODY" not in revoked_resp.text
        assert "messages" not in revoked_resp.json()

        # 2) Bot disabled while Discord fetch is in flight -> 503, zero message content
        tokens_2 = _complete_oauth_login(client, client_state="inflight-2")
        state["action"] = "disable_bot"

        disabled_resp = client.get(
            "/api/v1/guilds/g-1/channels/ch-1/messages",
            headers={"Authorization": f"Bearer {tokens_2['access_token']}"},
        )
        assert disabled_resp.status_code == 503
        assert disabled_resp.json()["code"] == "bot_unavailable"
        assert "TOP_SECRET_MESSAGE_BODY" not in disabled_resp.text
        assert "messages" not in disabled_resp.json()

        # Ensure guilds_json was captured cleanly in oauth_tickets during callback
        state["action"] = "none"
        repo.set_bot_enabled(True)
        row = (
            repo._require_conn().execute("SELECT guilds_json FROM oauth_tickets LIMIT 1").fetchone()
        )
        assert row is not None
        assert json.loads(row["guilds_json"]) == [
            {"id": "g-1", "name": "Guild One", "channels": []}
        ]

    repo.close()


def test_channels_calls_bot_guilds_only_once_per_request(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    repo = OrbRepository(settings.orb_db_path)
    calls_log: list[str] = []
    discord_client = DiscordClient(
        settings,
        transport=_build_discord_mock(calls_log=calls_log),
    )
    app = create_app(settings, repository=repo, discord_client=discord_client)

    with TestClient(app) as client:
        tokens = _complete_oauth_login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}

        calls_log.clear()
        resp_1 = client.get("/api/v1/channels", headers=headers)
        assert resp_1.status_code == 200
        assert calls_log.count("GET /api/v10/users/@me/guilds") == 1
        assert calls_log.count("GET /api/v10/users/@me") == 1

        calls_log.clear()
        resp_2 = client.get("/api/v1/channels", headers=headers)
        assert resp_2.status_code == 200
        assert calls_log.count("GET /api/v10/users/@me/guilds") == 1
        assert calls_log.count("GET /api/v10/users/@me") == 0

    repo.close()
