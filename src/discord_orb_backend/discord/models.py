"""Pydantic data models and structured exception hierarchy for Discord API."""

from __future__ import annotations

from pydantic import BaseModel, Field


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
    channels: list[DiscordChannel] = Field(default_factory=list)


class DiscordMessage(BaseModel):
    """Minimal Discord channel message for Orb preview."""

    id: str
    author_name: str
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
