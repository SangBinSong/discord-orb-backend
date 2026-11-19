"""Tests for Discord permission helpers, models, exceptions, and DiscordClient."""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

from discord_orb_backend.config import Settings
from discord_orb_backend.discord import (
    READ_MESSAGE_HISTORY,
    REQUIRED_PERMISSIONS,
    VIEW_CHANNEL,
    BotChannelStatus,
    DiscordAccessDeniedError,
    DiscordApiError,
    DiscordBotUnavailableError,
    DiscordClient,
    DiscordGuild,
    DiscordMessage,
    DiscordRateLimitError,
    DiscordUser,
    has_read_permissions,
    is_eligible_text_channel,
    parse_permissions,
)


def _make_settings(
    *,
    client_id: str = "test-client-id",
    client_secret: str = "test-client-secret",
    bot_token: str = "test-bot-token",
) -> Settings:
    return Settings(
        orb_public_url="https://orb.example.com",
        orb_db_path=":memory:",
        orb_discord_client_id=client_id,
        orb_discord_client_secret=client_secret,
        orb_discord_bot_token=bot_token,
        orb_session_secret="test-session-secret",
    )


def _mock_transport(
    handler: Callable[[httpx.Request], httpx.Response],
) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def test_permission_constants_and_parsing() -> None:
    assert VIEW_CHANNEL == 1 << 10
    assert READ_MESSAGE_HISTORY == 1 << 16
    assert REQUIRED_PERMISSIONS == (VIEW_CHANNEL | READ_MESSAGE_HISTORY)

    assert parse_permissions(str(REQUIRED_PERMISSIONS)) == REQUIRED_PERMISSIONS
    assert parse_permissions(f"  {VIEW_CHANNEL}  ") == VIEW_CHANNEL
    assert parse_permissions(0) == 0
    assert parse_permissions(REQUIRED_PERMISSIONS) == REQUIRED_PERMISSIONS

    # Fail-closed cases
    assert parse_permissions(None) is None
    assert parse_permissions(True) is None
    assert parse_permissions(False) is None
    assert parse_permissions(-1) is None
    assert parse_permissions("") is None
    assert parse_permissions("   ") is None
    assert parse_permissions("-1024") is None
    assert parse_permissions("+1024") is None
    assert parse_permissions("1_024") is None
    assert parse_permissions("abc") is None

    assert has_read_permissions(str(REQUIRED_PERMISSIONS)) is True
    assert has_read_permissions(str(VIEW_CHANNEL)) is False
    assert has_read_permissions(str(READ_MESSAGE_HISTORY)) is False
    assert has_read_permissions(None) is False
    assert has_read_permissions("invalid") is False


def test_is_eligible_text_channel() -> None:
    assert is_eligible_text_channel({"id": "1", "type": 0, "nsfw": False}) is True
    assert is_eligible_text_channel({"id": "1", "type": 0}) is True
    assert is_eligible_text_channel({"id": "1", "type": 0, "nsfw": None}) is True

    # Excluded channel types and NSFW/ambiguous payloads
    assert is_eligible_text_channel({"id": "1", "type": 0, "nsfw": True}) is False
    assert is_eligible_text_channel({"id": "1", "type": 0, "nsfw": "false"}) is False
    assert is_eligible_text_channel({"id": "1", "type": 2, "nsfw": False}) is False
    assert is_eligible_text_channel({"id": "1", "type": 4, "nsfw": False}) is False
    assert is_eligible_text_channel({"id": "1", "type": 11, "nsfw": False}) is False
    assert is_eligible_text_channel({"id": "1", "type": False, "nsfw": False}) is False
    assert is_eligible_text_channel("not-a-dict") is False


async def test_oauth_exchange_code_for_user_and_guilds_discards_token() -> None:
    seen_requests: list[tuple[str, str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_requests.append(
            (request.method, request.url.path, request.headers.get("Authorization"))
        )
        if request.url.path == "/api/v10/oauth2/token":
            body = request.content.decode("utf-8")
            assert "grant_type=authorization_code" in body
            assert "code=auth-code-123" in body
            return httpx.Response(200, json={"access_token": "ephemeral-user-token"})
        if request.url.path == "/api/v10/users/@me":
            return httpx.Response(
                200,
                json={"id": "user-1", "username": "alice", "global_name": "Alice"},
            )
        if request.url.path == "/api/v10/users/@me/guilds":
            return httpx.Response(
                200,
                json=[
                    {"id": "guild-1", "name": "Orb Guild"},
                    {"id": "guild-2", "name": "Other Guild"},
                ],
            )
        return httpx.Response(404)

    async with DiscordClient(_make_settings(), transport=_mock_transport(handler)) as client:
        user, guilds = await client.exchange_code_for_user_and_guilds(
            "auth-code-123",
            "https://orb.example.com/auth/callback",
        )
        assert user == DiscordUser(id="user-1", username="alice", global_name="Alice")
        assert guilds == [
            DiscordGuild(id="guild-1", name="Orb Guild"),
            DiscordGuild(id="guild-2", name="Other Guild"),
        ]
        # OAuth access token must never be stored on the client instance
        assert "ephemeral-user-token" not in json.dumps(
            {k: str(v) for k, v in client.__dict__.items()}
        )

    assert seen_requests == [
        ("POST", "/api/v10/oauth2/token", None),
        ("GET", "/api/v10/users/@me", "Bearer ephemeral-user-token"),
        ("GET", "/api/v10/users/@me/guilds", "Bearer ephemeral-user-token"),
    ]


async def test_oauth_exchange_code_for_user() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v10/oauth2/token":
            return httpx.Response(200, json={"access_token": "ephemeral-op-token"})
        if request.url.path == "/api/v10/users/@me":
            return httpx.Response(200, json={"id": "op-1", "username": "operator"})
        return httpx.Response(404)

    async with DiscordClient(_make_settings(), transport=_mock_transport(handler)) as client:
        user = await client.exchange_code_for_user("op-code", "https://orb.example.com/cb")
        assert user == DiscordUser(id="op-1", username="operator", global_name=None)


async def test_oauth_missing_credentials_raises_api_error() -> None:
    settings = _make_settings(client_id="", client_secret="")
    async with DiscordClient(
        settings, transport=_mock_transport(lambda _: httpx.Response(200))
    ) as c:
        with pytest.raises(DiscordApiError):
            await c.exchange_code_for_user("code", "https://orb.example.com/cb")


async def test_bot_unavailable_when_token_missing_or_unauthorized() -> None:
    no_token_client = DiscordClient(
        _make_settings(bot_token=""),
        transport=_mock_transport(lambda _: httpx.Response(200)),
    )
    async with no_token_client:
        with pytest.raises(DiscordBotUnavailableError):
            await no_token_client.get_bot_user_id()

    unauthorized_client = DiscordClient(
        _make_settings(),
        transport=_mock_transport(lambda _: httpx.Response(401, json={"message": "Unauthorized"})),
    )
    async with unauthorized_client:
        with pytest.raises(DiscordBotUnavailableError):
            await unauthorized_client.get_bot_user_id()


async def test_get_member_permissions_fail_closed_and_rate_limit() -> None:
    responses = [
        httpx.Response(200, json={"permissions": str(REQUIRED_PERMISSIONS)}),
        httpx.Response(403, json={"message": "Missing Access"}),
        httpx.Response(200, json={"permissions": "not-a-number"}),
        httpx.Response(200, content=b"not-json"),
        httpx.Response(429, headers={"Retry-After": "2.5"}, json={"retry_after": 2.5}),
    ]

    def handler(_: httpx.Request) -> httpx.Response:
        return responses.pop(0)

    async with DiscordClient(_make_settings(), transport=_mock_transport(handler)) as client:
        assert await client.get_member_permissions("ch-1", "u-1") == REQUIRED_PERMISSIONS
        assert await client.get_member_permissions("ch-1", "u-1") is None
        assert await client.get_member_permissions("ch-1", "u-1") is None
        assert await client.get_member_permissions("ch-1", "u-1") is None
        with pytest.raises(DiscordRateLimitError) as exc_info:
            await client.get_member_permissions("ch-1", "u-1")
        assert exc_info.value.retry_after == 2.5


async def test_list_eligible_channels_for_user_filters_by_intersection_type_nsfw_and_both_perms() -> (
    None
):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v10/users/@me":
            return httpx.Response(200, json={"id": "bot-1", "username": "orb-bot"})
        if path == "/api/v10/users/@me/guilds":
            return httpx.Response(
                200,
                json=[
                    {"id": "guild-1", "name": "Shared Guild"},
                    {"id": "guild-bot-only", "name": "Bot Only"},
                ],
            )
        if path == "/api/v10/guilds/guild-1/channels":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "ch-ok",
                        "guild_id": "guild-1",
                        "name": "general",
                        "type": 0,
                        "nsfw": False,
                    },
                    {
                        "id": "ch-nsfw",
                        "guild_id": "guild-1",
                        "name": "nsfw-room",
                        "type": 0,
                        "nsfw": True,
                    },
                    {
                        "id": "ch-voice",
                        "guild_id": "guild-1",
                        "name": "voice",
                        "type": 2,
                        "nsfw": False,
                    },
                    {
                        "id": "ch-bot-denied",
                        "guild_id": "guild-1",
                        "name": "secret-bot",
                        "type": 0,
                        "nsfw": False,
                    },
                    {
                        "id": "ch-user-denied",
                        "guild_id": "guild-1",
                        "name": "secret-user",
                        "type": 0,
                        "nsfw": False,
                    },
                ],
            )
        if path == "/api/v10/channels/ch-ok/permissions/member/bot-1":
            return httpx.Response(200, json={"permissions": str(REQUIRED_PERMISSIONS)})
        if path == "/api/v10/channels/ch-ok/permissions/member/user-1":
            return httpx.Response(200, json={"permissions": str(REQUIRED_PERMISSIONS)})
        if path == "/api/v10/channels/ch-bot-denied/permissions/member/bot-1":
            return httpx.Response(200, json={"permissions": str(VIEW_CHANNEL)})
        if path == "/api/v10/channels/ch-user-denied/permissions/member/bot-1":
            return httpx.Response(200, json={"permissions": str(REQUIRED_PERMISSIONS)})
        if path == "/api/v10/channels/ch-user-denied/permissions/member/user-1":
            return httpx.Response(200, json={"permissions": str(VIEW_CHANNEL)})
        return httpx.Response(404)

    user_guilds = [
        DiscordGuild(id="guild-1", name="Shared Guild"),
        DiscordGuild(id="guild-user-only", name="User Only"),
    ]
    async with DiscordClient(_make_settings(), transport=_mock_transport(handler)) as client:
        result = await client.list_eligible_channels_for_user("user-1", user_guilds)

    assert len(result) == 1
    assert result[0].id == "guild-1"
    assert [ch.id for ch in result[0].channels] == ["ch-ok"]
    assert [ch.name for ch in result[0].channels] == ["general"]


async def test_list_bot_channel_statuses_reports_unreadable_channels() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v10/users/@me":
            return httpx.Response(200, json={"id": "bot-1", "username": "orb-bot"})
        if path == "/api/v10/users/@me/guilds":
            return httpx.Response(200, json=[{"id": "g-1", "name": "Guild One"}])
        if path == "/api/v10/guilds/g-1/channels":
            return httpx.Response(
                200,
                json=[
                    {"id": "ch-readable", "name": "general", "type": 0, "nsfw": False},
                    {"id": "ch-unreadable", "name": "announcements", "type": 0, "nsfw": False},
                    {"id": "ch-hidden", "name": "private", "type": 0, "nsfw": False},
                ],
            )
        if path == "/api/v10/channels/ch-readable/permissions/member/bot-1":
            return httpx.Response(200, json={"permissions": str(REQUIRED_PERMISSIONS)})
        if path == "/api/v10/channels/ch-unreadable/permissions/member/bot-1":
            return httpx.Response(200, json={"permissions": str(VIEW_CHANNEL)})
        if path == "/api/v10/channels/ch-hidden/permissions/member/bot-1":
            return httpx.Response(200, json={"permissions": "0"})
        return httpx.Response(404)

    async with DiscordClient(_make_settings(), transport=_mock_transport(handler)) as client:
        statuses = await client.list_bot_channel_statuses()

    assert statuses == [
        BotChannelStatus(
            guild_id="g-1",
            guild_name="Guild One",
            channel_id="ch-readable",
            channel_name="general",
            can_view=True,
            can_read_history=True,
            unreadable=False,
        ),
        BotChannelStatus(
            guild_id="g-1",
            guild_name="Guild One",
            channel_id="ch-unreadable",
            channel_name="announcements",
            can_view=True,
            can_read_history=False,
            unreadable=True,
        ),
        BotChannelStatus(
            guild_id="g-1",
            guild_name="Guild One",
            channel_id="ch-hidden",
            channel_name="private",
            can_view=False,
            can_read_history=False,
            unreadable=False,
        ),
    ]


async def test_fetch_latest_messages_for_user_success_and_limits() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v10/guilds/g-1/channels":
            return httpx.Response(
                200,
                json=[
                    {"id": "ch-1", "guild_id": "g-1", "name": "general", "type": 0, "nsfw": False}
                ],
            )
        if path == "/api/v10/users/@me":
            return httpx.Response(200, json={"id": "bot-1", "username": "orb-bot"})
        if path == "/api/v10/channels/ch-1/permissions/member/bot-1":
            return httpx.Response(200, json={"permissions": str(REQUIRED_PERMISSIONS)})
        if path == "/api/v10/channels/ch-1/permissions/member/user-1":
            return httpx.Response(200, json={"permissions": str(REQUIRED_PERMISSIONS)})
        if path == "/api/v10/channels/ch-1/messages":
            assert request.url.params.get("limit") == "10"
            return httpx.Response(
                200,
                json=[
                    {
                        "id": f"msg-{i}",
                        "author": {
                            "username": f"user{i}",
                            "global_name": f"User {i}" if i % 2 == 0 else None,
                        },
                        "timestamp": f"2026-11-19T12:00:0{i}+00:00",
                        "content": f"hello {i}",
                    }
                    for i in range(12)
                ],
            )
        return httpx.Response(404)

    async with DiscordClient(_make_settings(), transport=_mock_transport(handler)) as client:
        messages = await client.fetch_latest_messages_for_user("g-1", "ch-1", "user-1", limit=25)

    assert len(messages) == 10
    assert messages[0] == DiscordMessage(
        id="msg-0",
        author_name="User 0",
        timestamp="2026-11-19T12:00:00+00:00",
        content="hello 0",
    )
    assert messages[1] == DiscordMessage(
        id="msg-1",
        author_name="user1",
        timestamp="2026-11-19T12:00:01+00:00",
        content="hello 1",
    )


async def test_fetch_latest_messages_rejects_ineligible_channel_or_missing_perms() -> None:
    def handler_ineligible(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v10/guilds/g-1/channels":
            return httpx.Response(
                200,
                json=[
                    {"id": "ch-nsfw", "guild_id": "g-1", "name": "nsfw", "type": 0, "nsfw": True}
                ],
            )
        return httpx.Response(404)

    async with DiscordClient(_make_settings(), transport=_mock_transport(handler_ineligible)) as c:
        with pytest.raises(DiscordAccessDeniedError):
            await c.fetch_latest_messages_for_user("g-1", "ch-nsfw", "user-1")

    def handler_bot_lacks_perms(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v10/guilds/g-1/channels":
            return httpx.Response(
                200,
                json=[
                    {"id": "ch-1", "guild_id": "g-1", "name": "general", "type": 0, "nsfw": False}
                ],
            )
        if path == "/api/v10/users/@me":
            return httpx.Response(200, json={"id": "bot-1", "username": "orb-bot"})
        if path == "/api/v10/channels/ch-1/permissions/member/bot-1":
            return httpx.Response(200, json={"permissions": str(VIEW_CHANNEL)})
        return httpx.Response(404)

    async with DiscordClient(
        _make_settings(), transport=_mock_transport(handler_bot_lacks_perms)
    ) as c:
        with pytest.raises(DiscordBotUnavailableError):
            await c.fetch_latest_messages_for_user("g-1", "ch-1", "user-1")

    def handler_user_lacks_perms(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v10/guilds/g-1/channels":
            return httpx.Response(
                200,
                json=[
                    {"id": "ch-1", "guild_id": "g-1", "name": "general", "type": 0, "nsfw": False}
                ],
            )
        if path == "/api/v10/users/@me":
            return httpx.Response(200, json={"id": "bot-1", "username": "orb-bot"})
        if path == "/api/v10/channels/ch-1/permissions/member/bot-1":
            return httpx.Response(200, json={"permissions": str(REQUIRED_PERMISSIONS)})
        if path == "/api/v10/channels/ch-1/permissions/member/user-1":
            return httpx.Response(500, json={"message": "Internal Error"})
        return httpx.Response(404)

    async with DiscordClient(
        _make_settings(), transport=_mock_transport(handler_user_lacks_perms)
    ) as c:
        with pytest.raises(DiscordAccessDeniedError):
            await c.fetch_latest_messages_for_user("g-1", "ch-1", "user-1")


async def test_injected_client_is_not_closed_on_aclose() -> None:
    injected = httpx.AsyncClient(
        base_url="https://discord.com/api/v10",
        transport=_mock_transport(
            lambda _: httpx.Response(200, json={"id": "bot-1", "username": "b"})
        ),
    )
    discord_client = DiscordClient(_make_settings(), client=injected)
    assert await discord_client.get_bot_user_id() == "bot-1"
    await discord_client.aclose()
    assert injected.is_closed is False
    await injected.aclose()
