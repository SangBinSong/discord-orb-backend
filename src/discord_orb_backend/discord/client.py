"""Async Discord REST API client for OAuth, discovery, permission checks, and messages."""

from __future__ import annotations

import hashlib
import math
from typing import Any, Self

import httpx

from ..config import Settings
from .models import (
    BotChannelStatus,
    DiscordAccessDeniedError,
    DiscordApiError,
    DiscordBotUnavailableError,
    DiscordChannel,
    DiscordGuild,
    DiscordMessage,
    DiscordRateLimitError,
    DiscordUser,
    resolve_author_avatar_url,
    resolve_guild_icon_url,
)
from .permissions import (
    READ_MESSAGE_HISTORY,
    VIEW_CHANNEL,
    has_permission,
    has_read_permissions,
    is_eligible_text_channel,
    parse_permissions,
)

DISCORD_API_BASE_URL = "https://discord.com/api/v10"
_MAX_MESSAGES_LIMIT = 10


def _parse_retry_after(response: httpx.Response) -> float:
    """Extract a non-negative Retry-After delay in seconds from a 429 response."""
    header_value = response.headers.get("Retry-After")
    if header_value is not None:
        try:
            parsed = float(header_value)
            if math.isfinite(parsed) and parsed >= 0:
                return parsed
        except ValueError:
            pass

    try:
        body = response.json()
    except ValueError:
        body = None

    if isinstance(body, dict):
        raw_retry = body.get("retry_after")
        if isinstance(raw_retry, (int, float)) and not isinstance(raw_retry, bool):
            parsed = float(raw_retry)
            if math.isfinite(parsed) and parsed >= 0:
                return parsed

    return 1.0


def _parse_user_payload(payload: Any) -> DiscordUser:
    if not isinstance(payload, dict):
        raise DiscordApiError("Discord user payload is not a JSON object")
    user_id = payload.get("id")
    username = payload.get("username")
    if not user_id or not username:
        raise DiscordApiError("Discord user payload is missing required fields")
    global_name = payload.get("global_name")
    return DiscordUser(
        id=str(user_id),
        username=str(username),
        global_name=str(global_name) if global_name is not None else None,
    )


def _parse_guilds_payload(payload: Any) -> list[DiscordGuild]:
    if not isinstance(payload, list):
        raise DiscordApiError("Discord guilds payload is not a JSON list")
    guilds: list[DiscordGuild] = []
    for item in payload:
        if not isinstance(item, dict):
            raise DiscordApiError("Discord guild entry is not a JSON object")
        guild_id = item.get("id")
        name = item.get("name")
        if not guild_id or name is None:
            raise DiscordApiError("Discord guild entry is missing required fields")
        guild_id_str = str(guild_id)
        guilds.append(
            DiscordGuild(
                id=guild_id_str,
                name=str(name),
                guild_icon_url=resolve_guild_icon_url(guild_id_str, item.get("icon")),
            )
        )
    return guilds


class DiscordClient:
    """Async client wrapping Discord OAuth and Bot REST API endpoints."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        client: httpx.AsyncClient | None = None,
        base_url: str = DISCORD_API_BASE_URL,
    ) -> None:
        self._settings = settings
        self._cached_bot_user: tuple[bytes, str] | None = None
        if client is not None:
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.AsyncClient(
                base_url=base_url,
                transport=transport,
                timeout=10.0,
            )
            self._owns_client = True

    async def aclose(self) -> None:
        """Close the underlying HTTP client if owned by this instance."""
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    def _require_bot_token(self) -> str:
        token = self._settings.orb_discord_bot_token
        if not token:
            raise DiscordBotUnavailableError("Discord bot token is not configured")
        return token

    def _bot_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bot {self._require_bot_token()}"}

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        bot_auth: bool = False,
    ) -> Any:
        try:
            response = await self._client.request(
                method,
                path,
                headers=headers,
                params=params,
                data=data,
            )
        except httpx.HTTPError as exc:
            raise DiscordApiError(f"Discord HTTP request failed: {exc}") from exc

        if response.status_code == 429:
            raise DiscordRateLimitError(_parse_retry_after(response))

        if bot_auth and response.status_code in (401, 403, 404):
            raise DiscordBotUnavailableError(
                f"Discord bot unavailable or unauthorized (HTTP {response.status_code})",
                status_code=response.status_code,
            )

        if response.is_error:
            raise DiscordApiError(
                f"Discord API returned HTTP {response.status_code}",
                status_code=response.status_code,
            )

        try:
            return response.json()
        except ValueError as exc:
            raise DiscordApiError(
                "Discord API returned invalid JSON",
                status_code=response.status_code,
            ) from exc

    async def _exchange_code_for_access_token(self, code: str, redirect_uri: str) -> str:
        client_id = self._settings.orb_discord_client_id
        client_secret = self._settings.orb_discord_client_secret
        if not client_id or not client_secret:
            raise DiscordApiError("Discord OAuth client credentials are not configured")

        payload = await self._request_json(
            "POST",
            "/oauth2/token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
            },
        )
        if not isinstance(payload, dict):
            raise DiscordApiError("Discord OAuth token response is not a JSON object")
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise DiscordApiError("Discord OAuth token response is missing access_token")
        return access_token

    async def _fetch_oauth_user(self, access_token: str) -> DiscordUser:
        payload = await self._request_json(
            "GET",
            "/users/@me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        return _parse_user_payload(payload)

    async def exchange_code_for_user(self, code: str, redirect_uri: str) -> DiscordUser:
        """Exchange an OAuth authorization code for user identity (token is not retained)."""
        access_token = await self._exchange_code_for_access_token(code, redirect_uri)
        return await self._fetch_oauth_user(access_token)

    async def exchange_code_for_user_and_guilds(
        self,
        code: str,
        redirect_uri: str,
    ) -> tuple[DiscordUser, list[DiscordGuild]]:
        """Exchange an OAuth code for user identity and guilds, then discard the token."""
        access_token = await self._exchange_code_for_access_token(code, redirect_uri)
        bearer_headers = {"Authorization": f"Bearer {access_token}"}
        user = await self._fetch_oauth_user(access_token)
        guilds_payload = await self._request_json(
            "GET",
            "/users/@me/guilds",
            headers=bearer_headers,
        )
        return user, _parse_guilds_payload(guilds_payload)

    async def get_bot_user_id(self) -> str:
        """Return the authenticated bot's Discord user ID, cached per bot token."""
        token = self._require_bot_token()
        token_key = hashlib.sha256(token.encode("utf-8")).digest()
        if self._cached_bot_user is not None and self._cached_bot_user[0] == token_key:
            return self._cached_bot_user[1]

        self._cached_bot_user = None
        payload = await self._request_json(
            "GET",
            "/users/@me",
            headers={"Authorization": f"Bot {token}"},
            bot_auth=True,
        )
        bot_user_id = _parse_user_payload(payload).id
        self._cached_bot_user = (token_key, bot_user_id)
        return bot_user_id

    async def list_bot_guilds(self) -> list[DiscordGuild]:
        """Return the guilds the bot currently belongs to."""
        payload = await self._request_json(
            "GET",
            "/users/@me/guilds",
            headers=self._bot_headers(),
            bot_auth=True,
        )
        return _parse_guilds_payload(payload)

    async def list_guild_channels(self, guild_id: str) -> list[DiscordChannel]:
        """Return eligible non-NSFW text channels (type == 0) in a guild."""
        payload = await self._request_json(
            "GET",
            f"/guilds/{guild_id}/channels",
            headers=self._bot_headers(),
            bot_auth=True,
        )
        if not isinstance(payload, list):
            raise DiscordApiError("Discord guild channels payload is not a JSON list")

        channels: list[DiscordChannel] = []
        for item in payload:
            if not is_eligible_text_channel(item):
                continue
            channel_id = item.get("id")
            name = item.get("name")
            if not channel_id or name is None:
                continue
            channels.append(
                DiscordChannel(
                    id=str(channel_id),
                    guild_id=str(item.get("guild_id") or guild_id),
                    name=str(name),
                    type=0,
                    nsfw=False,
                )
            )
        return channels

    async def get_member_permissions(self, channel_id: str, user_id: str) -> int | None:
        """Fetch real-time effective channel permissions for a member, failing closed to None."""
        headers = self._bot_headers()
        try:
            response = await self._client.request(
                "GET",
                f"/channels/{channel_id}/permissions/member/{user_id}",
                headers=headers,
            )
        except httpx.HTTPError:
            return None

        if response.status_code == 429:
            raise DiscordRateLimitError(_parse_retry_after(response))

        if response.is_error:
            return None

        try:
            payload = response.json()
        except ValueError:
            return None

        if not isinstance(payload, dict):
            return None
        return parse_permissions(payload.get("permissions"))

    async def list_eligible_channels_for_user(
        self,
        user_id: str,
        user_guilds: list[DiscordGuild] | None = None,
    ) -> list[DiscordGuild]:
        """Return shared guilds containing only channels readable by both bot and user."""
        bot_user_id = await self.get_bot_user_id()
        bot_guilds = await self.list_bot_guilds()
        bot_guilds_by_id = {guild.id: guild for guild in bot_guilds}
        if user_guilds is None:
            candidate_guilds = bot_guilds
        else:
            candidate_guilds = [guild for guild in user_guilds if guild.id in bot_guilds_by_id]

        eligible_guilds: list[DiscordGuild] = []
        for guild in candidate_guilds:
            channels = await self.list_guild_channels(guild.id)
            eligible_channels: list[DiscordChannel] = []
            for channel in channels:
                bot_perms = await self.get_member_permissions(channel.id, bot_user_id)
                if not has_read_permissions(bot_perms):
                    continue
                user_perms = await self.get_member_permissions(channel.id, user_id)
                if not has_read_permissions(user_perms):
                    continue
                eligible_channels.append(channel)

            bot_guild = bot_guilds_by_id.get(guild.id)
            icon_url = (
                guild.guild_icon_url
                if guild.guild_icon_url is not None
                else (bot_guild.guild_icon_url if bot_guild is not None else None)
            )
            eligible_guilds.append(
                DiscordGuild(
                    id=guild.id,
                    name=guild.name,
                    guild_icon_url=icon_url,
                    channels=eligible_channels,
                )
            )
        return eligible_guilds

    async def list_bot_channel_statuses(self) -> list[BotChannelStatus]:
        """Return bot permission status across all eligible text channels in bot guilds."""
        bot_user_id = await self.get_bot_user_id()
        bot_guilds = await self.list_bot_guilds()

        statuses: list[BotChannelStatus] = []
        for guild in bot_guilds:
            channels = await self.list_guild_channels(guild.id)
            for channel in channels:
                bot_perms = await self.get_member_permissions(channel.id, bot_user_id)
                can_view = has_permission(bot_perms, VIEW_CHANNEL)
                can_read_history = has_permission(bot_perms, READ_MESSAGE_HISTORY)
                statuses.append(
                    BotChannelStatus(
                        guild_id=guild.id,
                        guild_name=guild.name,
                        channel_id=channel.id,
                        channel_name=channel.name,
                        can_view=can_view,
                        can_read_history=can_read_history,
                        unreadable=can_view and not can_read_history,
                    )
                )
        return statuses

    async def verify_channel_access_for_user(
        self,
        guild_id: str,
        channel_id: str,
        user_id: str,
    ) -> None:
        """Verify eligible channel membership, bot permissions, and user permissions fail-closed."""
        channels = await self.list_guild_channels(guild_id)
        if not any(channel.id == channel_id for channel in channels):
            raise DiscordAccessDeniedError(
                f"Channel {channel_id} is not an eligible text channel in guild {guild_id}"
            )

        bot_user_id = await self.get_bot_user_id()
        bot_perms = await self.get_member_permissions(channel_id, bot_user_id)
        if not has_read_permissions(bot_perms):
            raise DiscordBotUnavailableError(
                f"Bot lacks required read permissions for channel {channel_id}"
            )

        user_perms = await self.get_member_permissions(channel_id, user_id)
        if not has_read_permissions(user_perms):
            raise DiscordAccessDeniedError(
                f"User {user_id} lacks required read permissions for channel {channel_id}"
            )

    async def fetch_latest_messages_for_user(
        self,
        guild_id: str,
        channel_id: str,
        user_id: str,
        limit: int = 10,
    ) -> list[DiscordMessage]:
        """Verify channel membership, bot permissions, and user permissions, then fetch messages."""
        await self.verify_channel_access_for_user(guild_id, channel_id, user_id)

        resolved_limit = min(max(limit, 1), _MAX_MESSAGES_LIMIT)
        payload = await self._request_json(
            "GET",
            f"/channels/{channel_id}/messages",
            headers=self._bot_headers(),
            params={"limit": resolved_limit},
            bot_auth=True,
        )
        if not isinstance(payload, list):
            raise DiscordApiError("Discord messages payload is not a JSON list")

        messages: list[DiscordMessage] = []
        for item in payload[:resolved_limit]:
            if not isinstance(item, dict):
                raise DiscordApiError("Discord message entry is not a JSON object")
            message_id = item.get("id")
            timestamp = item.get("timestamp")
            if not message_id or not timestamp:
                raise DiscordApiError("Discord message entry is missing required fields")
            author = item.get("author")
            if isinstance(author, dict):
                author_name = author.get("global_name") or author.get("username") or "Unknown"
            else:
                author_name = "Unknown"
            content = item.get("content")
            messages.append(
                DiscordMessage(
                    id=str(message_id),
                    author_name=str(author_name),
                    author_avatar_url=resolve_author_avatar_url(item, guild_id=guild_id),
                    timestamp=str(timestamp),
                    content=str(content) if content is not None else "",
                )
            )
        return messages
