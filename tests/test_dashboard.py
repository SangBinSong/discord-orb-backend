"""Tests for the hosting operator web dashboard, auth, CSRF, bot toggle, and session revoke."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from discord_orb_backend.config import Settings
from discord_orb_backend.dashboard.operator_auth import (
    OPERATOR_OAUTH_STATE_COOKIE_NAME,
    OPERATOR_SESSION_COOKIE_NAME,
)
from discord_orb_backend.discord import (
    BotChannelStatus,
    DiscordApiError,
    DiscordBotUnavailableError,
    DiscordUser,
)
from discord_orb_backend.main import create_app
from discord_orb_backend.storage import Repository


class FakeDiscordClient:
    """In-memory test double for DiscordClient used by dashboard tests."""

    def __init__(
        self,
        *,
        oauth_user: DiscordUser | None = None,
        channel_statuses: list[BotChannelStatus] | None = None,
        channel_error: Exception | None = None,
    ) -> None:
        self.oauth_user = oauth_user or DiscordUser(
            id="op-1",
            username="operator",
            global_name="Operator",
        )
        self.channel_statuses = list(channel_statuses) if channel_statuses is not None else []
        self.channel_error = channel_error
        self.exchange_calls: list[tuple[str, str]] = []
        self.list_bot_channel_statuses_calls = 0

    async def exchange_code_for_user(self, code: str, redirect_uri: str) -> DiscordUser:
        self.exchange_calls.append((code, redirect_uri))
        return self.oauth_user

    async def list_bot_channel_statuses(self) -> list[BotChannelStatus]:
        self.list_bot_channel_statuses_calls += 1
        if self.channel_error is not None:
            raise self.channel_error
        return list(self.channel_statuses)


def _make_settings(
    *,
    operator_ids: tuple[str, ...] = ("op-1",),
    bot_token: str = "fake-bot-token-secret",
    db_path: str = ":memory:",
) -> Settings:
    return Settings(
        orb_public_url="https://orb.example.com",
        orb_db_path=db_path,
        orb_discord_client_id="test-client-id",
        orb_discord_client_secret="test-client-secret-value",
        orb_discord_bot_token=bot_token,
        orb_operator_discord_ids=operator_ids,
        orb_session_secret="test-session-secret-value",
    )


def _extract_csrf_token(html_text: str) -> str:
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html_text)
    assert match is not None, "Expected csrf_token hidden input in HTML"
    return match.group(1)


def _sign_in_operator(client: TestClient) -> str:
    login_resp = client.get("/dashboard/login", follow_redirects=False)
    assert login_resp.status_code == 302
    parsed = urlparse(login_resp.headers["location"])
    state = parse_qs(parsed.query)["state"][0]

    callback_resp = client.get(
        "/dashboard/callback",
        params={"code": "oauth-code-123", "state": state},
        follow_redirects=False,
    )
    assert callback_resp.status_code == 303
    assert callback_resp.headers["location"] == "/dashboard"

    dash_resp = client.get("/dashboard")
    assert dash_resp.status_code == 200
    return _extract_csrf_token(dash_resp.text)


def test_dashboard_returns_503_when_oauth_unconfigured() -> None:
    settings = Settings(orb_db_path=":memory:")
    app = create_app(settings, repository=Repository(":memory:"))
    with TestClient(app, base_url="https://orb.example.com") as client:
        assert client.get("/dashboard").status_code == 503
        assert client.get("/dashboard/login").status_code == 503


def test_operator_oauth_login_and_cookie_attributes() -> None:
    settings = _make_settings(operator_ids=("op-1",))
    repo = Repository(":memory:")
    discord = FakeDiscordClient(oauth_user=DiscordUser(id="op-1", username="alice"))
    app = create_app(settings, repository=repo, discord_client=discord)

    with TestClient(app, base_url="https://orb.example.com") as client:
        login_resp = client.get("/dashboard/login", follow_redirects=False)
        assert login_resp.status_code == 302

        location = login_resp.headers["location"]
        parsed = urlparse(location)
        assert parsed.scheme == "https"
        assert parsed.netloc == "discord.com"
        assert parsed.path == "/oauth2/authorize"
        query = parse_qs(parsed.query)
        assert query["client_id"] == ["test-client-id"]
        assert query["response_type"] == ["code"]
        assert query["redirect_uri"] == ["https://orb.example.com/dashboard/callback"]
        assert query["scope"] == ["identify"]
        state = query["state"][0]

        state_cookie = login_resp.headers.get("set-cookie", "")
        assert OPERATOR_OAUTH_STATE_COOKIE_NAME in state_cookie
        assert "HttpOnly" in state_cookie
        assert "Secure" in state_cookie

        callback_resp = client.get(
            "/dashboard/callback",
            params={"code": "code-abc", "state": state},
            follow_redirects=False,
        )
        assert callback_resp.status_code == 303
        assert callback_resp.headers["location"] == "/dashboard"
        assert discord.exchange_calls == [
            ("code-abc", "https://orb.example.com/dashboard/callback")
        ]

        session_cookie_header = "; ".join(callback_resp.headers.get_list("set-cookie"))
        assert OPERATOR_SESSION_COOKIE_NAME in session_cookie_header
        assert "Max-Age=900" in session_cookie_header
        assert "HttpOnly" in session_cookie_header
        assert "Secure" in session_cookie_header
        assert "SameSite=lax" in session_cookie_header
        assert "refresh_token" not in session_cookie_header.lower()


def test_callback_denies_empty_allowlist_and_non_operator_and_bad_state() -> None:
    discord = FakeDiscordClient(oauth_user=DiscordUser(id="regular-user", username="bob"))

    # Empty allowlist grants access to nobody
    empty_allowlist_app = create_app(
        _make_settings(operator_ids=()),
        repository=Repository(":memory:"),
        discord_client=discord,
    )
    with TestClient(empty_allowlist_app, base_url="https://orb.example.com") as client:
        login_resp = client.get("/dashboard/login", follow_redirects=False)
        state = parse_qs(urlparse(login_resp.headers["location"]).query)["state"][0]
        resp = client.get(
            "/dashboard/callback",
            params={"code": "code-1", "state": state},
            follow_redirects=False,
        )
        assert resp.status_code == 403
        assert OPERATOR_SESSION_COOKIE_NAME not in resp.cookies

    # Non-allowlisted user is denied 403
    non_op_app = create_app(
        _make_settings(operator_ids=("op-1",)),
        repository=Repository(":memory:"),
        discord_client=discord,
    )
    with TestClient(non_op_app, base_url="https://orb.example.com") as client:
        login_resp = client.get("/dashboard/login", follow_redirects=False)
        state = parse_qs(urlparse(login_resp.headers["location"]).query)["state"][0]

        bad_state_resp = client.get(
            "/dashboard/callback",
            params={"code": "code-1", "state": "wrong-state"},
            follow_redirects=False,
        )
        assert bad_state_resp.status_code == 403
        assert OPERATOR_SESSION_COOKIE_NAME not in bad_state_resp.cookies

        denied_resp = client.get(
            "/dashboard/callback",
            params={"code": "code-1", "state": state},
            follow_redirects=False,
        )
        assert denied_resp.status_code == 403
        assert OPERATOR_SESSION_COOKIE_NAME not in denied_resp.cookies


def test_rejects_unauthenticated_bearer_tokens_and_tampered_cookies() -> None:
    settings = _make_settings(operator_ids=("op-1",))
    repo = Repository(":memory:")
    discord = FakeDiscordClient()
    app = create_app(settings, repository=repo, discord_client=discord)

    with TestClient(app, base_url="https://orb.example.com") as client:
        assert client.get("/dashboard").status_code == 401
        assert (
            client.get(
                "/dashboard",
                headers={"Authorization": "Bearer flutter-access-token"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/dashboard/bot/toggle",
                headers={"Authorization": "Bearer flutter-access-token"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/dashboard/sessions/session-1/revoke",
                headers={"Authorization": "Bearer flutter-access-token"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/dashboard/logout",
                headers={"Authorization": "Bearer flutter-access-token"},
            ).status_code
            == 401
        )

        # Tampered cookie is rejected
        client.cookies.set(OPERATOR_SESSION_COOKIE_NAME, "tampered.cookie.value")
        tampered = client.get("/dashboard")
        assert tampered.status_code == 401


def test_operator_session_fixed_15_min_expiry_and_per_request_allowlist_recheck(
    monkeypatch: Any,
) -> None:
    current_time = 1_700_000_000.0
    monkeypatch.setattr(
        "discord_orb_backend.dashboard.operator_auth.time.time",
        lambda: current_time,
    )

    settings = _make_settings(operator_ids=("op-1",))
    repo = Repository(":memory:")
    discord = FakeDiscordClient(oauth_user=DiscordUser(id="op-1", username="operator"))
    app = create_app(settings, repository=repo, discord_client=discord)

    with TestClient(app, base_url="https://orb.example.com") as client:
        _sign_in_operator(client)

        # Still valid at 14m59s
        current_time = 1_700_000_000.0 + 899.0
        assert client.get("/dashboard").status_code == 200

        # Allowlist removal immediately denies an otherwise unexpired session
        app.state.settings = _make_settings(operator_ids=())
        assert client.get("/dashboard").status_code == 403

        # Restore allowlist, then cross the fixed 15-minute boundary -> expired
        app.state.settings = settings
        current_time = 1_700_000_000.0 + 900.0
        expired_resp = client.get("/dashboard")
        assert expired_resp.status_code == 401


def test_csrf_required_and_bound_to_operator_session() -> None:
    settings = _make_settings(operator_ids=("op-1", "op-2"))
    repo = Repository(":memory:")
    discord = FakeDiscordClient(oauth_user=DiscordUser(id="op-1", username="operator1"))
    app = create_app(settings, repository=repo, discord_client=discord)

    with TestClient(app, base_url="https://orb.example.com") as client_a:
        csrf_a = _sign_in_operator(client_a)

        # Missing CSRF -> 403
        assert client_a.post("/dashboard/bot/toggle", follow_redirects=False).status_code == 403
        assert (
            client_a.post("/dashboard/sessions/abc/revoke", follow_redirects=False).status_code
            == 403
        )
        assert client_a.post("/dashboard/logout", follow_redirects=False).status_code == 403

        # Invalid CSRF -> 403
        assert (
            client_a.post(
                "/dashboard/bot/toggle",
                data={"csrf_token": "bad.token"},
                follow_redirects=False,
            ).status_code
            == 403
        )

        # CSRF from a second operator session is rejected on client_a
        discord.oauth_user = DiscordUser(id="op-2", username="operator2")
        with TestClient(app, base_url="https://orb.example.com") as client_b:
            csrf_b = _sign_in_operator(client_b)
            assert (
                client_a.post(
                    "/dashboard/bot/toggle",
                    data={"csrf_token": csrf_b},
                    follow_redirects=False,
                ).status_code
                == 403
            )
            assert (
                client_b.post(
                    "/dashboard/bot/toggle",
                    headers={"X-CSRF-Token": csrf_a},
                    follow_redirects=False,
                ).status_code
                == 403
            )

        # Valid CSRF header works too
        ok_resp = client_a.post(
            "/dashboard/bot/toggle",
            headers={"X-CSRF-Token": csrf_a},
            follow_redirects=False,
        )
        assert ok_resp.status_code == 303


def test_bot_channel_statuses_unreadable_and_bot_unavailable() -> None:
    settings = _make_settings(operator_ids=("op-1",))
    repo = Repository(":memory:")
    discord = FakeDiscordClient(
        channel_statuses=[
            BotChannelStatus(
                guild_id="g1",
                guild_name="Orb Server",
                channel_id="c1",
                channel_name="general",
                can_view=True,
                can_read_history=True,
                unreadable=False,
            ),
            BotChannelStatus(
                guild_id="g1",
                guild_name="Orb Server",
                channel_id="c2",
                channel_name="announcements-no-history",
                can_view=True,
                can_read_history=False,
                unreadable=True,
            ),
        ]
    )
    app = create_app(settings, repository=repo, discord_client=discord)

    with TestClient(app, base_url="https://orb.example.com") as client:
        _sign_in_operator(client)
        page = client.get("/dashboard")
        assert page.status_code == 200
        html = page.text
        assert "Orb Server" in html
        assert "#general" in html
        assert "#announcements-no-history" in html
        assert "VIEW_CHANNEL" in html
        assert "READ_MESSAGE_HISTORY" in html
        assert "unreadable" in html
        assert "test-client-secret-value" not in html
        assert "fake-bot-token-secret" not in html
        assert "test-session-secret-value" not in html

    # When bot token is missing, show Bot token unavailable without crashing
    no_bot_settings = _make_settings(operator_ids=("op-1",), bot_token="")
    no_bot_app = create_app(no_bot_settings, repository=Repository(":memory:"), discord_client=None)
    with TestClient(no_bot_app, base_url="https://orb.example.com") as client:
        login_resp = client.get("/dashboard/login", follow_redirects=False)
        assert login_resp.status_code == 302
        # Inject fake discord client only for OAuth callback, with bot_configured=False
        no_bot_app.state.discord_client = FakeDiscordClient(
            channel_error=DiscordBotUnavailableError("missing")
        )
        _sign_in_operator(client)
        page = client.get("/dashboard")
        assert page.status_code == 200
        assert "Bot token unavailable" in page.text

    # When Discord API fails with DiscordApiError, dashboard remains usable
    failing_discord = FakeDiscordClient(channel_error=DiscordApiError("upstream 500"))
    err_app = create_app(
        settings, repository=Repository(":memory:"), discord_client=failing_discord
    )
    with TestClient(err_app, base_url="https://orb.example.com") as client:
        _sign_in_operator(client)
        page = client.get("/dashboard")
        assert page.status_code == 200
        assert "Unable to fetch Discord channel permissions" in page.text


def test_bot_toggle_persists_skips_discord_calls_and_supports_htmx(tmp_path: Path) -> None:
    db_file = str(tmp_path / "orb.db")
    settings = _make_settings(operator_ids=("op-1",), db_path=db_file)
    discord = FakeDiscordClient(
        channel_statuses=[
            BotChannelStatus(
                guild_id="g1",
                guild_name="Orb Server",
                channel_id="c1",
                channel_name="general",
                can_view=True,
                can_read_history=True,
                unreadable=False,
            )
        ]
    )

    app1 = create_app(settings, discord_client=discord)
    with TestClient(app1, base_url="https://orb.example.com") as client:
        csrf = _sign_in_operator(client)
        assert discord.list_bot_channel_statuses_calls == 1

        # HTMX toggle off -> partial HTML with Bot preview disabled, no Discord bot call
        hx_off = client.post(
            "/dashboard/bot/toggle",
            data={"csrf_token": csrf},
            headers={"HX-Request": "true"},
        )
        assert hx_off.status_code == 200
        assert 'id="bot-panel"' in hx_off.text
        assert "Bot preview disabled" in hx_off.text
        assert discord.list_bot_channel_statuses_calls == 1

        # Reloading full dashboard while disabled still skips Discord bot calls
        dash_disabled = client.get("/dashboard")
        assert dash_disabled.status_code == 200
        assert "Bot preview disabled" in dash_disabled.text
        assert discord.list_bot_channel_statuses_calls == 1

    # Recreate app against the same SQLite DB -> bot_enabled=False persisted
    app2 = create_app(settings, discord_client=discord)
    with TestClient(app2, base_url="https://orb.example.com") as client2:
        csrf2 = _sign_in_operator(client2)
        assert "Bot preview disabled" in client2.get("/dashboard").text
        assert discord.list_bot_channel_statuses_calls == 1

        # Standard form POST toggle back on -> 303 redirect and resumes channel listing
        form_on = client2.post(
            "/dashboard/bot/toggle",
            data={"csrf_token": csrf2, "enabled": "true"},
            follow_redirects=False,
        )
        assert form_on.status_code == 303
        assert form_on.headers["location"] == "/dashboard"

        re_enabled = client2.get("/dashboard")
        assert re_enabled.status_code == 200
        assert "#general" in re_enabled.text
        assert discord.list_bot_channel_statuses_calls == 2


def test_active_sessions_escape_xss_hide_sensitive_fields_and_revoke_exact_session_id() -> None:
    settings = _make_settings(operator_ids=("op-1",))
    repo = Repository(":memory:")
    xss_name = '<script>alert("xss")</script>'
    session_a = repo.create_session(
        discord_user_id="secret-flutter-user-999",
        device_name=xss_name,
        device_id="shared-device-id",
        platform="macos",
        refresh_token="secret-refresh-token-alpha",
    )
    session_b = repo.create_session(
        discord_user_id="secret-flutter-user-888",
        device_name="Android Pixel",
        device_id="shared-device-id",
        platform="android",
        refresh_token="secret-refresh-token-beta",
    )
    discord = FakeDiscordClient()
    app = create_app(settings, repository=repo, discord_client=discord)

    with TestClient(app, base_url="https://orb.example.com") as client:
        csrf = _sign_in_operator(client)
        page = client.get("/dashboard")
        assert page.status_code == 200
        html = page.text

        # Device fields present and untrusted device_name is HTML-escaped
        assert xss_name not in html
        assert "&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;" in html
        assert "shared-device-id" in html
        assert "macos" in html
        assert "Android Pixel" in html
        assert "android" in html

        # Sensitive data never exposed
        assert "secret-flutter-user-999" not in html
        assert "secret-flutter-user-888" not in html
        assert "secret-refresh-token-alpha" not in html
        assert "secret-refresh-token-beta" not in html
        assert session_a.current_refresh_token_hash not in html
        assert session_b.current_refresh_token_hash not in html

        # Revoke session_a via HTMX -> only session_a is revoked, session_b remains active
        hx_revoke = client.post(
            f"/dashboard/sessions/{session_a.session_id}/revoke",
            data={"csrf_token": csrf},
            headers={"HX-Request": "true"},
        )
        assert hx_revoke.status_code == 200
        assert 'id="sessions-panel"' in hx_revoke.text
        assert "Android Pixel" in hx_revoke.text
        assert "&lt;script&gt;alert" not in hx_revoke.text

        assert repo.is_session_active(session_a.session_id) is False
        assert repo.is_session_active(session_b.session_id) is True

        # Revoke session_b via standard form POST -> 303 redirect
        form_revoke = client.post(
            f"/dashboard/sessions/{session_b.session_id}/revoke",
            data={"csrf_token": _extract_csrf_token(hx_revoke.text)},
            follow_redirects=False,
        )
        assert form_revoke.status_code == 303
        assert form_revoke.headers["location"] == "/dashboard"
        assert repo.is_session_active(session_b.session_id) is False
        assert "No active Flutter sessions." in client.get("/dashboard").text


def test_operator_logout_clears_session_cookie() -> None:
    settings = _make_settings(operator_ids=("op-1",))
    repo = Repository(":memory:")
    discord = FakeDiscordClient()
    app = create_app(settings, repository=repo, discord_client=discord)

    with TestClient(app, base_url="https://orb.example.com") as client:
        csrf = _sign_in_operator(client)
        logout_resp = client.post(
            "/dashboard/logout",
            data={"csrf_token": csrf},
            follow_redirects=False,
        )
        assert logout_resp.status_code == 303
        assert logout_resp.headers["location"] == "/dashboard"
        assert client.get("/dashboard").status_code == 401
