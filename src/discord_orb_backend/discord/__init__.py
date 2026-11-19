"""Discord API client, models, exceptions, and permission helpers."""

from .client import DiscordClient
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
)
from .permissions import (
    READ_MESSAGE_HISTORY,
    REQUIRED_PERMISSIONS,
    VIEW_CHANNEL,
    has_permission,
    has_read_permissions,
    is_eligible_text_channel,
    parse_permissions,
)

__all__ = [
    "READ_MESSAGE_HISTORY",
    "REQUIRED_PERMISSIONS",
    "VIEW_CHANNEL",
    "BotChannelStatus",
    "DiscordAccessDeniedError",
    "DiscordApiError",
    "DiscordBotUnavailableError",
    "DiscordChannel",
    "DiscordClient",
    "DiscordGuild",
    "DiscordMessage",
    "DiscordRateLimitError",
    "DiscordUser",
    "has_permission",
    "has_read_permissions",
    "is_eligible_text_channel",
    "parse_permissions",
]
