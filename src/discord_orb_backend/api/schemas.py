"""Pydantic request and response schemas for the Flutter client HTTP API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class ErrorResponse(BaseModel):
    """Structured JSON error payload returned by API routes."""

    code: str
    detail: str


class AuthExchangeRequest(BaseModel):
    """Request body for exchanging a single-use OAuth ticket + PKCE verifier."""

    ticket: str = Field(min_length=1)
    code_verifier: str = Field(min_length=1, max_length=256)
    device_name: str = Field(min_length=1, max_length=200)
    device_id: str = Field(min_length=1, max_length=200)
    platform: Literal["android", "macos", "windows"]
    redirect_uri: str | None = None

    @field_validator("ticket", "code_verifier", "device_name", "device_id")
    @classmethod
    def _require_non_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Field must not be blank")
        return stripped


class AuthTokensResponse(BaseModel):
    """Issued Flutter access/refresh tokens and UTC expiration timestamps."""

    access_token: str
    refresh_token: str
    access_expires_at: str
    session_expires_at: str


class AuthRefreshRequest(BaseModel):
    """Request body for rotating a Flutter refresh token."""

    refresh_token: str = Field(min_length=1)

    @field_validator("refresh_token")
    @classmethod
    def _require_non_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("refresh_token must not be blank")
        return stripped


class AuthLogoutRequest(BaseModel):
    """Optional request body for revoking a session during logout."""

    refresh_token: str | None = None


class AuthLogoutResponse(BaseModel):
    """Response payload confirming session revocation."""

    revoked: bool


class ChannelItem(BaseModel):
    """Eligible Discord text channel metadata."""

    guild_id: str
    guild_name: str
    guild_icon_url: str | None = None
    channel_id: str
    channel_name: str


class GuildChannelsItem(BaseModel):
    """Discord guild containing one or more eligible text channels."""

    guild_id: str
    guild_name: str
    guild_icon_url: str | None = None
    channels: list[ChannelItem]


class ChannelsResponse(BaseModel):
    """Grouped eligible guilds and channels for the authenticated user."""

    guilds: list[GuildChannelsItem]


class MessageItem(BaseModel):
    """Text-only Discord message preview entry."""

    id: str
    author_name: str
    author_avatar_url: str | None = None
    timestamp: str
    content: str


class ChannelMessagesResponse(BaseModel):
    """Latest message previews for a single verified Discord channel."""

    guild_id: str
    channel_id: str
    messages: list[MessageItem]
