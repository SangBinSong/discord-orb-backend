"""Authenticated channel discovery and real-time message preview routes."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, status
from fastapi.responses import JSONResponse

from ..config import Settings
from ..dependencies import get_discord_client, get_repository, get_settings
from ..discord import (
    DiscordAccessDeniedError,
    DiscordApiError,
    DiscordBotUnavailableError,
    DiscordRateLimitError,
)
from .schemas import (
    ChannelItem,
    ChannelMessagesResponse,
    ChannelsResponse,
    GuildChannelsItem,
    MessageItem,
)
from .tokens import (
    AccessTokenClaims,
    InvalidTokenError,
    TokenExpiredError,
    verify_access_token,
)

_NO_STORE_HEADERS = {"Cache-Control": "no-store"}
_MAX_PREVIEW_MESSAGES = 10

router = APIRouter(prefix="/api/v1", tags=["preview"])


def _json_error(
    status_code: int,
    code: str,
    detail: str,
    *,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    merged_headers = dict(_NO_STORE_HEADERS)
    if headers:
        merged_headers.update(headers)
    return JSONResponse(
        status_code=status_code,
        content={"code": code, "detail": detail},
        headers=merged_headers,
    )


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token if token else None


def _inactive_session_error(repository: Any, session_id: str) -> JSONResponse:
    get_session = getattr(repository, "get_session", None)
    session = get_session(session_id) if callable(get_session) else None
    if (
        session is not None
        and session.revoked_at is None
        and session.session_expires_at <= datetime.now(UTC)
    ):
        return _json_error(
            status.HTTP_401_UNAUTHORIZED,
            "session_expired",
            "Session has expired",
        )
    return _json_error(
        status.HTTP_401_UNAUTHORIZED,
        "session_revoked",
        "Session has been revoked",
    )


def _authenticate_request(
    authorization: str | None,
    settings: Settings,
    repository: Any,
) -> tuple[AccessTokenClaims | None, JSONResponse | None]:
    token = _extract_bearer_token(authorization)
    if token is None:
        return None, _json_error(
            status.HTTP_401_UNAUTHORIZED,
            "session_revoked",
            "Missing or invalid Bearer token",
        )

    try:
        claims = verify_access_token(token, settings.orb_session_secret)
    except TokenExpiredError:
        return None, _json_error(
            status.HTTP_401_UNAUTHORIZED,
            "token_expired",
            "Access token has expired",
        )
    except InvalidTokenError:
        return None, _json_error(
            status.HTTP_401_UNAUTHORIZED,
            "invalid_token",
            "Invalid access token",
        )

    if not repository.is_session_active(claims.session_id):
        return None, _inactive_session_error(repository, claims.session_id)

    return claims, None


def _check_bot_available(settings: Settings, repository: Any) -> JSONResponse | None:
    if not settings.bot_configured or not repository.is_bot_enabled():
        return _json_error(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "bot_unavailable",
            "Discord bot is unavailable or disabled",
        )
    return None


def _check_in_flight_state(
    claims: AccessTokenClaims,
    settings: Settings,
    repository: Any,
) -> JSONResponse | None:
    if not repository.is_session_active(claims.session_id):
        return _inactive_session_error(repository, claims.session_id)
    if not settings.bot_configured or not repository.is_bot_enabled():
        return _json_error(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "bot_unavailable",
            "Discord bot is unavailable or disabled",
        )
    return None


def _map_discord_error(exc: DiscordApiError) -> JSONResponse:
    if isinstance(exc, DiscordAccessDeniedError):
        return _json_error(status.HTTP_403_FORBIDDEN, "access_denied", str(exc))
    if isinstance(exc, DiscordBotUnavailableError):
        return _json_error(status.HTTP_503_SERVICE_UNAVAILABLE, "bot_unavailable", str(exc))
    if isinstance(exc, DiscordRateLimitError):
        retry_after = str(max(0, math.ceil(exc.retry_after)))
        return _json_error(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "rate_limited",
            str(exc),
            headers={"Retry-After": retry_after},
        )
    return _json_error(
        status.HTTP_502_BAD_GATEWAY,
        "discord_api_error",
        "Discord API request failed",
    )


@router.get("/channels", response_model=ChannelsResponse)
async def list_channels(
    settings: Annotated[Settings, Depends(get_settings)],
    repository: Annotated[Any, Depends(get_repository)],
    discord_client: Annotated[Any, Depends(get_discord_client)],
    authorization: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    """List standard text channels readable by both the shared bot and signed-in user."""
    claims, auth_error = _authenticate_request(authorization, settings, repository)
    if auth_error is not None or claims is None:
        return auth_error  # type: ignore[return-value]

    bot_error = _check_bot_available(settings, repository)
    if bot_error is not None:
        return bot_error

    try:
        eligible_guilds = await discord_client.list_eligible_channels_for_user(
            claims.discord_user_id,
        )
    except DiscordApiError as exc:
        return _map_discord_error(exc)

    in_flight_error = _check_in_flight_state(claims, settings, repository)
    if in_flight_error is not None:
        eligible_guilds = []
        return in_flight_error

    grouped = [
        GuildChannelsItem(
            guild_id=guild.id,
            guild_name=guild.name,
            channels=[
                ChannelItem(
                    guild_id=guild.id,
                    guild_name=guild.name,
                    channel_id=channel.id,
                    channel_name=channel.name,
                )
                for channel in guild.channels
            ],
        )
        for guild in eligible_guilds
        if guild.channels
    ]
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=ChannelsResponse(guilds=grouped).model_dump(),
        headers=_NO_STORE_HEADERS,
    )


@router.get(
    "/guilds/{guild_id}/channels/{channel_id}/messages",
    response_model=ChannelMessagesResponse,
)
async def get_channel_messages(
    guild_id: str,
    channel_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
    repository: Annotated[Any, Depends(get_repository)],
    discord_client: Annotated[Any, Depends(get_discord_client)],
    authorization: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    """Verify real-time bot/user access and return up to 10 latest channel messages."""
    claims, auth_error = _authenticate_request(authorization, settings, repository)
    if auth_error is not None or claims is None:
        return auth_error  # type: ignore[return-value]

    bot_error = _check_bot_available(settings, repository)
    if bot_error is not None:
        return bot_error

    try:
        messages = await discord_client.fetch_latest_messages_for_user(
            guild_id,
            channel_id,
            claims.discord_user_id,
            limit=_MAX_PREVIEW_MESSAGES,
        )
    except DiscordApiError as exc:
        return _map_discord_error(exc)

    in_flight_error = _check_in_flight_state(claims, settings, repository)
    if in_flight_error is not None:
        # Discard fetched messages completely when session/bot became invalid mid-flight.
        messages = []
        return in_flight_error

    payload = ChannelMessagesResponse(
        guild_id=guild_id,
        channel_id=channel_id,
        messages=[
            MessageItem(
                id=msg.id,
                author_name=msg.author_name,
                timestamp=msg.timestamp,
                content=msg.content,
            )
            for msg in messages[:_MAX_PREVIEW_MESSAGES]
        ],
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=payload.model_dump(),
        headers=_NO_STORE_HEADERS,
    )
