"""Discord permission bitmask parsing and channel eligibility helpers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

VIEW_CHANNEL: int = 1 << 10
READ_MESSAGE_HISTORY: int = 1 << 16
REQUIRED_PERMISSIONS: int = VIEW_CHANNEL | READ_MESSAGE_HISTORY

GUILD_TEXT_CHANNEL_TYPE: int = 0


def parse_permissions(raw: str | int | None) -> int | None:
    """Parse a Discord permission bitmask, failing closed to None on invalid input."""
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw >= 0 else None
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped or not stripped.isascii() or not stripped.isdigit():
            return None
        return int(stripped, 10)
    return None


def has_permission(raw: str | int | None, bit: int) -> bool:
    """Return True only when the parsed bitmask includes all bits in `bit`."""
    parsed = parse_permissions(raw)
    if parsed is None:
        return False
    return (parsed & bit) == bit


def has_read_permissions(raw: str | int | None) -> bool:
    """Return True only when both VIEW_CHANNEL and READ_MESSAGE_HISTORY are granted."""
    return has_permission(raw, REQUIRED_PERMISSIONS)


def is_eligible_text_channel(channel_payload: Mapping[str, Any] | Any) -> bool:
    """Return True only for non-NSFW standard guild text channels (type == 0)."""
    if not isinstance(channel_payload, Mapping):
        return False

    channel_type = channel_payload.get("type")
    if isinstance(channel_type, bool) or channel_type != GUILD_TEXT_CHANNEL_TYPE:
        return False

    nsfw = channel_payload.get("nsfw", False)
    if nsfw is None:
        return True
    if isinstance(nsfw, bool):
        return not nsfw
    return False
