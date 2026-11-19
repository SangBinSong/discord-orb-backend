"""End-to-end backend integration tests covering OAuth, previews, dashboard, and persistence."""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
from fastapi.testclient import TestClient

from discord_orb_backend.config import Settings
from discord_orb_backend.discord import (
    REQUIRED_PERMISSIONS,
    VIEW_CHANNEL,
    DiscordClient,
)
from discord_orb_backend.main import create_app

TEST_SESSION_SECRET = "e2e-synthetic-session-secret-0123456789"


def _make_pkce_pair(verifier: str) -> tuple[str, str]:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _extract_csrf_token(html_text: str) -> str:
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html_text)
    assert match is not None, "Expected csrf_token hidden input in dashboard HTML"
    return match.group(1)


class _MutableDiscordMock:
    """Mutable Discord HTTP transport simulating live OAuth and permission changes."""

    def __init__(self) -> None:
        self.oauth_user = {"id": "user-alice", "username": "alice", "global_name": "Alice"}
        self.user_guilds = [
            {"id": "g-1", "name": "Orb Guild"},
            {"id": "g-user-only", "name": "No Bot Guild"},
        ]
        self.bot_guilds = [
            {"id": "g-1", "name": "Orb Guild"},
            {"id": "g-bot-only", "name": "Bot Only Guild"},
        ]
        self.channels_by_guild = {
            "g-1": [
                {"id": "ch-open", "guild_id": "g-1", "name": "general", "type": 0, "nsfw": False},
                {
                    "id": "ch-secret",
                    "guild_id": "g-1",
                    "name": "staff-only",
                    "type": 0,
                    "nsfw": False,
                },
                {"id": "ch-nsfw", "guild_id": "g-1", "name": "nsfw-room", "type": 0, "nsfw": True},
                {"id": "ch-voice", "guild_id": "g-1", "name": "voice", "type": 2, "nsfw": False},
            ],
            "g-bot-only": [
                {
                    "id": "ch-bot-only",
                    "guild_id": "g-bot-only",
                    "name": "internal",
                    "type": 0,
                    "nsfw": False,
                }
            ],
        }
        self.perms: dict[tuple[str, str], int] = {
            ("ch-open", "bot-1"): REQUIRED_PERMISSIONS,
            ("ch-open", "user-alice"): REQUIRED_PERMISSIONS,
            ("ch-open", "user-bob"): REQUIRED_PERMISSIONS,
            ("ch-secret", "bot-1"): REQUIRED_PERMISSIONS,
            ("ch-secret", "user-alice"): VIEW_CHANNEL,
            ("ch-bot-only", "bot-1"): REQUIRED_PERMISSIONS,
        }
        self.messages_by_channel = {
            "ch-open": [
                {
                    "id": f"msg-{i}",
                    "author": {"username": f"author{i}", "global_name": f"Author {i}"},
                    "timestamp": f"2026-11-19T10:{i:02d}:00+00:00",
                    "content": f"Synthetic message {i}",
                }
                for i in range(15)
            ]
        }
        self.bot_calls_count = 0

    def build_client(self, settings: Settings) -> DiscordClient:
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bot "):
                self.bot_calls_count += 1

            if path == "/api/v10/oauth2/token":
                return httpx.Response(200, json={"access_token": "ephemeral-oauth-token"})

            if path == "/api/v10/users/@me":
                if auth.startswith("Bot "):
                    return httpx.Response(200, json={"id": "bot-1", "username": "orb-bot"})
                return httpx.Response(200, json=self.oauth_user)

            if path == "/api/v10/users/@me/guilds":
                if auth.startswith("Bot "):
                    return httpx.Response(200, json=self.bot_guilds)
                return httpx.Response(200, json=self.user_guilds)

            if path.startswith("/api/v10/guilds/") and path.endswith("/channels"):
                guild_id = path.split("/")[4]
                channels = self.channels_by_guild.get(guild_id)
                if channels is None:
                    return httpx.Response(404, json={"message": "Unknown Guild"})
                return httpx.Response(200, json=channels)

            if "/permissions/member/" in path:
                parts = path.split("/")
                channel_id = parts[4]
                user_id = parts[7]
                perm = self.perms.get((channel_id, user_id))
                if perm is None:
                    return httpx.Response(404, json={"message": "Unknown Member"})
                return httpx.Response(200, json={"permissions": str(perm)})

            if path.startswith("/api/v10/channels/") and path.endswith("/messages"):
                channel_id = path.split("/")[4]
                return httpx.Response(200, json=self.messages_by_channel.get(channel_id, []))

            return httpx.Response(404)

        return DiscordClient(settings, transport=httpx.MockTransport(handler))


def _perform_flutter_oauth(
    client: TestClient,
    *,
    redirect_uri: str,
    verifier: str,
    client_state: str,
    device_name: str,
    device_id: str,
    platform: str,
) -> dict[str, str]:
    _, challenge = _make_pkce_pair(verifier)
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
    server_state = parse_qs(urlparse(login_resp.headers["location"]).query)["state"][0]

    callback_resp = client.get(
        "/auth/discord/callback",
        params={"code": "discord-oauth-code", "state": server_state},
        follow_redirects=False,
    )
    assert callback_resp.status_code == 302
    app_redirect = callback_resp.headers["location"]
    assert "access_token" not in app_redirect
    assert "refresh_token" not in app_redirect

    query = parse_qs(urlparse(app_redirect).query)
    assert query["state"] == [client_state]
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

    # Single-use ticket must reject replay.
    replay_resp = client.post(
        "/api/v1/auth/exchange",
        json={
            "ticket": ticket,
            "code_verifier": verifier,
            "device_name": device_name,
            "device_id": device_id,
            "platform": platform,
        },
    )
    assert replay_resp.status_code == 400
    assert replay_resp.json()["code"] == "invalid_ticket"

    return exchange_resp.json()


def _sign_in_operator(client: TestClient, discord_mock: _MutableDiscordMock) -> str:
    previous_user = discord_mock.oauth_user
    discord_mock.oauth_user = {"id": "op-1", "username": "operator", "global_name": "Operator"}
    try:
        login_resp = client.get("/dashboard/login", follow_redirects=False)
        assert login_resp.status_code == 302
        state = parse_qs(urlparse(login_resp.headers["location"]).query)["state"][0]

        callback_resp = client.get(
            "/dashboard/callback",
            params={"code": "op-oauth-code", "state": state},
            follow_redirects=False,
        )
        assert callback_resp.status_code == 303
        assert callback_resp.headers["location"] == "/dashboard"

        dash_resp = client.get("/dashboard")
        assert dash_resp.status_code == 200
        return _extract_csrf_token(dash_resp.text)
    finally:
        discord_mock.oauth_user = previous_user


def test_full_backend_e2e_flow_and_restart_persistence(tmp_path: Path) -> None:
    db_file = str(tmp_path / "orb-e2e.db")
    settings = Settings(
        orb_public_url="https://orb.example.com",
        orb_db_path=db_file,
        orb_discord_client_id="e2e-client-id",
        orb_discord_client_secret="e2e-client-secret",
        orb_discord_bot_token="e2e-bot-token",
        orb_operator_discord_ids=("op-1",),
        orb_session_secret=TEST_SESSION_SECRET,
    )
    discord_mock = _MutableDiscordMock()

    # Boot 1: verify OAuth, channel discovery, message preview, revocation, and bot disable.
    app1 = create_app(settings, discord_client=discord_mock.build_client(settings))
    with TestClient(app1, base_url="https://orb.example.com") as client:
        # 1. Alice logs in via desktop loopback PKCE flow; Bob logs in via Android scheme.
        alice_tokens = _perform_flutter_oauth(
            client,
            redirect_uri="http://127.0.0.1:51234/callback",
            verifier="alice-pkce-verifier-" + ("a" * 30),
            client_state="alice-state-1",
            device_name="Alice MacBook",
            device_id="dev-alice-1",
            platform="macos",
        )
        alice_headers = {"Authorization": f"Bearer {alice_tokens['access_token']}"}

        discord_mock.oauth_user = {"id": "user-bob", "username": "bob", "global_name": "Bob"}
        bob_tokens = _perform_flutter_oauth(
            client,
            redirect_uri="discordorb://auth/callback",
            verifier="bob-pkce-verifier-" + ("b" * 30),
            client_state="bob-state-1",
            device_name="Bob Pixel",
            device_id="dev-bob-1",
            platform="android",
        )
        bob_headers = {"Authorization": f"Bearer {bob_tokens['access_token']}"}
        discord_mock.oauth_user = {"id": "user-alice", "username": "alice", "global_name": "Alice"}

        # 2. Eligible channels only include ch-open (shared guild + readable by user & bot).
        channels_resp = client.get("/api/v1/channels", headers=alice_headers)
        assert channels_resp.status_code == 200
        assert channels_resp.json() == {
            "guilds": [
                {
                    "guild_id": "g-1",
                    "guild_name": "Orb Guild",
                    "channels": [
                        {
                            "guild_id": "g-1",
                            "guild_name": "Orb Guild",
                            "channel_id": "ch-open",
                            "channel_name": "general",
                        }
                    ],
                }
            ]
        }
        assert "staff-only" not in channels_resp.text
        assert "nsfw-room" not in channels_resp.text
        assert "Bot Only Guild" not in channels_resp.text

        # 3. Message preview returns up to 10 latest messages.
        preview_resp = client.get(
            "/api/v1/guilds/g-1/channels/ch-open/messages", headers=alice_headers
        )
        assert preview_resp.status_code == 200
        preview_body = preview_resp.json()
        assert len(preview_body["messages"]) == 10
        assert preview_body["messages"][0]["content"] == "Synthetic message 0"

        # 4. Revoke Alice's channel permission -> next preview blocked with 403 and 0 messages.
        discord_mock.perms[("ch-open", "user-alice")] = VIEW_CHANNEL
        denied_resp = client.get(
            "/api/v1/guilds/g-1/channels/ch-open/messages",
            headers=alice_headers,
        )
        assert denied_resp.status_code == 403
        assert denied_resp.json()["code"] == "access_denied"
        assert "Synthetic message" not in denied_resp.text

        # Bob still retains access while Alice lost it.
        bob_ok_resp = client.get(
            "/api/v1/guilds/g-1/channels/ch-open/messages", headers=bob_headers
        )
        assert bob_ok_resp.status_code == 200
        assert len(bob_ok_resp.json()["messages"]) == 10

        # 5. Operator signs in to dashboard and revokes Alice's session.
        csrf = _sign_in_operator(client, discord_mock)
        dash_html = client.get("/dashboard").text
        assert "Alice MacBook" in dash_html
        assert "Bob Pixel" in dash_html

        alice_session_match = re.search(
            r'action="/dashboard/sessions/([^/]+)/revoke".*?Alice MacBook',
            dash_html,
            re.DOTALL,
        )
        # Fallback if device name precedes action in row markup:
        if alice_session_match is None:
            alice_session_match = re.search(
                r'Alice MacBook.*?/dashboard/sessions/([^/"\']+)/revoke',
                dash_html,
                re.DOTALL,
            )
        assert alice_session_match is not None, "Expected Alice's session revoke URL in dashboard"
        alice_session_id = alice_session_match.group(1)

        revoke_resp = client.post(
            f"/dashboard/sessions/{alice_session_id}/revoke",
            data={"csrf_token": csrf},
            follow_redirects=False,
        )
        assert revoke_resp.status_code == 303

        # Existing access token AND refresh token for Alice are both rejected with 401.
        assert client.get("/api/v1/channels", headers=alice_headers).status_code == 401
        assert (
            client.get(
                "/api/v1/guilds/g-1/channels/ch-open/messages",
                headers=alice_headers,
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": alice_tokens["refresh_token"]},
            ).status_code
            == 401
        )

        # Bob's session remains active.
        assert client.get("/api/v1/channels", headers=bob_headers).status_code == 200

        # 6. Operator disables bot via dashboard -> preview blocked with 503 without Discord calls.
        toggle_off = client.post(
            "/dashboard/bot/toggle",
            data={"csrf_token": csrf, "enabled": "false"},
            follow_redirects=False,
        )
        assert toggle_off.status_code == 303
        assert "Bot preview disabled" in client.get("/dashboard").text

        calls_before = discord_mock.bot_calls_count
        bob_channels_blocked = client.get("/api/v1/channels", headers=bob_headers)
        assert bob_channels_blocked.status_code == 503
        assert bob_channels_blocked.json()["code"] == "bot_unavailable"

        bob_msg_blocked = client.get(
            "/api/v1/guilds/g-1/channels/ch-open/messages",
            headers=bob_headers,
        )
        assert bob_msg_blocked.status_code == 503
        assert bob_msg_blocked.json()["code"] == "bot_unavailable"
        assert discord_mock.bot_calls_count == calls_before

    # Boot 2: recreate app pointing to the same SQLite DB file (container restart simulation).
    app2 = create_app(settings, discord_client=discord_mock.build_client(settings))
    with TestClient(app2, base_url="https://orb.example.com") as client2:
        # Bot disabled state persists across restart.
        assert (
            client2.get(
                "/api/v1/guilds/g-1/channels/ch-open/messages",
                headers=bob_headers,
            ).status_code
            == 503
        )

        # Alice's revoked access & refresh tokens remain 401 across restart.
        assert client2.get("/api/v1/channels", headers=alice_headers).status_code == 401
        assert (
            client2.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": alice_tokens["refresh_token"]},
            ).status_code
            == 401
        )

        # Dashboard stays reachable, shows disabled state, and allows re-enabling the bot.
        csrf2 = _sign_in_operator(client2, discord_mock)
        assert "Bot preview disabled" in client2.get("/dashboard").text

        toggle_on = client2.post(
            "/dashboard/bot/toggle",
            data={"csrf_token": csrf2, "enabled": "true"},
            follow_redirects=False,
        )
        assert toggle_on.status_code == 303

        # Bob's still-valid session immediately resumes previewing after re-enable.
        resumed_resp = client2.get(
            "/api/v1/guilds/g-1/channels/ch-open/messages",
            headers=bob_headers,
        )
        assert resumed_resp.status_code == 200
        assert len(resumed_resp.json()["messages"]) == 10
