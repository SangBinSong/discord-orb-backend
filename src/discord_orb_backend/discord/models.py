"""Pydantic data models and structured exception hierarchy for Discord API."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, Field

DISCORD_CDN_BASE_URL = "https://cdn.discordapp.com"


def resolve_guild_icon_url(guild_id: str | None, icon: Any) -> str | None:
    """Resolve a Discord guild icon CDN URL, or None when absent/empty."""
    resolved_guild_id = str(guild_id).strip() if guild_id is not None else ""
    if not resolved_guild_id or not isinstance(icon, str):
        return None
    resolved_icon = icon.strip()
    if not resolved_icon:
        return None
    return f"{DISCORD_CDN_BASE_URL}/icons/{resolved_guild_id}/{resolved_icon}.png?size=64"


def resolve_author_avatar_url(
    message_payload: Mapping[str, Any] | Any,
    *,
    guild_id: str | None = None,
) -> str | None:
    """Resolve the display avatar URL for a Discord message author.

    Priority:
      1. Guild member avatar (`member.avatar`) when `guild_id` and `author.id` exist.
      2. User avatar (`author.avatar`) when `author.id` exists.
      3. Discord default embed avatar when numeric `author.id` exists
         (legacy discriminator % 5 when numeric and != "0", else (id >> 22) % 6).
      4. None.
    """
    if not isinstance(message_payload, Mapping):
        return None

    author = message_payload.get("author")
    if not isinstance(author, Mapping):
        return None

    raw_user_id = author.get("id")
    user_id = str(raw_user_id).strip() if raw_user_id is not None else ""
    if not user_id:
        return None

    raw_guild_id = message_payload.get("guild_id")
    resolved_guild_id = (
        str(raw_guild_id).strip()
        if raw_guild_id is not None and str(raw_guild_id).strip()
        else (str(guild_id).strip() if guild_id is not None else "")
    )

    member = message_payload.get("member")
    if isinstance(member, Mapping) and resolved_guild_id:
        raw_member_avatar = member.get("avatar")
        if isinstance(raw_member_avatar, str) and raw_member_avatar.strip():
            member_avatar = raw_member_avatar.strip()
            return (
                f"{DISCORD_CDN_BASE_URL}/guilds/{resolved_guild_id}"
                f"/users/{user_id}/avatars/{member_avatar}.png?size=64"
            )

    raw_author_avatar = author.get("avatar")
    if isinstance(raw_author_avatar, str) and raw_author_avatar.strip():
        author_avatar = raw_author_avatar.strip()
        return f"{DISCORD_CDN_BASE_URL}/avatars/{user_id}/{author_avatar}.png?size=64"

    if user_id.isascii() and user_id.isdigit():
        raw_disc = author.get("discriminator")
        disc = str(raw_disc).strip() if raw_disc is not None else ""
        if disc and disc.isascii() and disc.isdigit() and disc != "0":
            index = int(disc) % 5
        else:
            index = (int(user_id) >> 22) % 6
        return f"{DISCORD_CDN_BASE_URL}/embed/avatars/{index}.png"

    return None


class DiscordApiError(Exception):
    """Base exception for Discord API communication or payload failures."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class DiscordRateLimitError(DiscordApiError):
    """Raised when Discord responds with HTTP 429 Too Many Requests."""

    def __init__(
        self,
        retry_after: float,
        message: str | None = None,
        *,
        status_code: int = 429,
    ) -> None:
        resolved_message = message or f"Discord rate limit exceeded; retry after {retry_after}s"
        super().__init__(resolved_message, status_code=status_code)
        self.retry_after = retry_after


class DiscordAccessDeniedError(DiscordApiError):
    """Raised when user permissions, channel membership, or eligibility fail closed."""


class DiscordBotUnavailableError(DiscordApiError):
    """Raised when the Discord bot token is missing, invalid, uninstalled, or lacks permissions."""


class DiscordUser(BaseModel):
    """Minimal Discord user identity."""

    id: str
    username: str
    global_name: str | None = None


class DiscordChannel(BaseModel):
    """Eligible Discord guild text channel."""

    id: str
    guild_id: str
    name: str
    type: int = 0
    nsfw: bool = False


class DiscordGuild(BaseModel):
    """Discord guild (server) with optional eligible channels."""

    id: str
    name: str
    guild_icon_url: str | None = None
    channels: list[DiscordChannel] = Field(default_factory=list)


class DiscordMessage(BaseModel):
    """Minimal Discord channel message for Orb preview."""

    id: str
    author_name: str
    author_avatar_url: str | None = None
    timestamp: str
    content: str


class BotChannelStatus(BaseModel):
    """Bot permission status for an eligible guild text channel (operator dashboard)."""

    guild_id: str
    guild_name: str
    channel_id: str
    channel_name: str
    can_view: bool
    can_read_history: bool
    unreadable: bool
