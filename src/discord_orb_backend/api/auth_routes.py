"""RFC 8252 OAuth login, callback, ticket exchange, refresh rotation, and logout routes."""

from __future__ import annotations

import hmac
import json
import math
import re
from datetime import UTC
from typing import Annotated, Any
from urllib.parse import urlencode

from fastapi import APIRouter, Body, Depends, Header, Query, status
from fastapi.responses import JSONResponse, RedirectResponse

from ..config import Settings
from ..dependencies import get_discord_client, get_repository, get_settings
from ..discord import DiscordApiError, DiscordRateLimitError
from ..storage import (
    InvalidOrExpiredTicketError,
    InvalidSessionError,
    RefreshTokenReusedError,
    SessionExpiredError,
    SessionRevokedError,
    hash_token,
)
from .schemas import (
    AuthExchangeRequest,
    AuthLogoutRequest,
    AuthLogoutResponse,
    AuthRefreshRequest,
    AuthTokensResponse,
)
from .tokens import (
    OAUTH_TICKET_TTL_SECONDS,
    SESSION_TTL_DAYS,
    TokenError,
    create_access_token,
    create_oauth_state_token,
    generate_oauth_ticket,
    generate_refresh_token,
    verify_access_token,
    verify_oauth_state_token,
    verify_pkce_s256,
)

DISCORD_AUTHORIZE_URL = "https://discord.com/oauth2/authorize"
ANDROID_REDIRECT_URI = "discordorb://auth/callback"
_LOOPBACK_REDIRECT_RE = re.compile(r"^http://127\.0\.0\.1:([0-9]{1,5})/callback$")
_NO_STORE_HEADERS = {"Cache-Control": "no-store"}

router = APIRouter(tags=["auth"])


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


def validate_app_redirect_uri(redirect_uri: str | None) -> str:
    """Validate that an app redirect_uri matches the allowed RFC 8252 targets."""
    if not redirect_uri:
        raise ValueError("redirect_uri is required")
    if redirect_uri == ANDROID_REDIRECT_URI:
        return redirect_uri

    match = _LOOPBACK_REDIRECT_RE.fullmatch(redirect_uri)
    if match is None:
        raise ValueError("Unsupported redirect_uri")
    port = int(match.group(1))
    if port < 1 or port > 65535:
        raise ValueError("Loopback port out of range")
    return redirect_uri


def _discord_callback_uri(settings: Settings) -> str:
    return f"{settings.orb_public_url.rstrip('/')}/auth/discord/callback"


def _append_query_params(base_uri: str, params: dict[str, str]) -> str:
    separator = "&" if "?" in base_uri else "?"
    return f"{base_uri}{separator}{urlencode(params)}"


def _is_valid_opaque_param(value: str | None, *, max_length: int = 512) -> bool:
    if not value:
        return False
    if len(value) > max_length:
        return False
    if any(ch.isspace() for ch in value):
        return False
    return value.isascii()


@router.get("/auth/discord/login", response_model=None)
async def discord_login(
    settings: Annotated[Settings, Depends(get_settings)],
    redirect_uri: str | None = Query(default=None),
    code_challenge: str | None = Query(default=None),
    code_challenge_method: str | None = Query(default=None),
    state: str | None = Query(default=None),
) -> RedirectResponse | JSONResponse:
    """Validate RFC 8252 PKCE parameters and redirect to Discord OAuth authorize."""
    try:
        validated_redirect = validate_app_redirect_uri(redirect_uri)
    except ValueError as exc:
        return _json_error(status.HTTP_400_BAD_REQUEST, "invalid_redirect_uri", str(exc))

    if code_challenge_method != "S256":
        return _json_error(
            status.HTTP_400_BAD_REQUEST,
            "invalid_request",
            "code_challenge_method must be S256",
        )

    if not _is_valid_opaque_param(code_challenge, max_length=256):
        return _json_error(
            status.HTTP_400_BAD_REQUEST,
            "invalid_request",
            "code_challenge is missing or invalid",
        )

    if not _is_valid_opaque_param(state, max_length=512):
        return _json_error(
            status.HTTP_400_BAD_REQUEST,
            "invalid_request",
            "state is missing or invalid",
        )

    assert code_challenge is not None
    assert state is not None

    server_state = create_oauth_state_token(
        redirect_uri=validated_redirect,
        code_challenge=code_challenge,
        client_state=state,
        secret=settings.orb_session_secret,
    )

    authorize_params = urlencode(
        {
            "client_id": settings.orb_discord_client_id,
            "response_type": "code",
            "redirect_uri": _discord_callback_uri(settings),
            "scope": "identify guilds",
            "state": server_state,
        }
    )
    return RedirectResponse(
        url=f"{DISCORD_AUTHORIZE_URL}?{authorize_params}",
        status_code=status.HTTP_302_FOUND,
        headers=_NO_STORE_HEADERS,
    )


@router.get("/auth/discord/callback", response_model=None)
async def discord_callback(
    settings: Annotated[Settings, Depends(get_settings)],
    repository: Annotated[Any, Depends(get_repository)],
    discord_client: Annotated[Any, Depends(get_discord_client)],
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
) -> RedirectResponse | JSONResponse:
    """Verify Discord OAuth callback, mint a single-use ticket, and redirect to app."""
    if not state:
        return _json_error(status.HTTP_400_BAD_REQUEST, "invalid_state", "Missing OAuth state")

    try:
        state_claims = verify_oauth_state_token(state, settings.orb_session_secret)
        app_redirect_uri = validate_app_redirect_uri(state_claims.redirect_uri)
    except (TokenError, ValueError) as exc:
        return _json_error(status.HTTP_400_BAD_REQUEST, "invalid_state", str(exc))

    if error:
        target = _append_query_params(
            app_redirect_uri,
            {"error": error, "state": state_claims.client_state},
        )
        return RedirectResponse(
            url=target,
            status_code=status.HTTP_302_FOUND,
            headers=_NO_STORE_HEADERS,
        )

    if not code or not code.strip():
        return _json_error(
            status.HTTP_400_BAD_REQUEST,
            "missing_code",
            "Missing Discord authorization code",
        )

    try:
        user, guilds = await discord_client.exchange_code_for_user_and_guilds(
            code.strip(),
            _discord_callback_uri(settings),
        )
    except DiscordRateLimitError as exc:
        retry_after = str(max(0, math.ceil(exc.retry_after)))
        return _json_error(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "rate_limited",
            "Discord OAuth rate limit exceeded",
            headers={"Retry-After": retry_after},
        )
    except DiscordApiError as exc:
        upstream_status = (
            status.HTTP_400_BAD_REQUEST
            if exc.status_code in (400, 401)
            else status.HTTP_502_BAD_GATEWAY
        )
        return _json_error(
            upstream_status,
            "discord_oauth_failed",
            "Discord OAuth code exchange failed",
        )

    ticket = generate_oauth_ticket()
    guilds_json = json.dumps([guild.model_dump(mode="json") for guild in guilds])
    repository.create_oauth_ticket(
        ticket=ticket,
        discord_user_id=user.id,
        guilds_json=guilds_json,
        pkce_code_challenge=state_claims.code_challenge,
        redirect_uri=app_redirect_uri,
        ttl_seconds=OAUTH_TICKET_TTL_SECONDS,
    )

    redirect_target = _append_query_params(
        app_redirect_uri,
        {"ticket": ticket, "state": state_claims.client_state},
    )
    return RedirectResponse(
        url=redirect_target,
        status_code=status.HTTP_302_FOUND,
        headers=_NO_STORE_HEADERS,
    )


@router.post("/api/v1/auth/exchange", response_model=AuthTokensResponse)
async def exchange_ticket(
    payload: AuthExchangeRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    repository: Annotated[Any, Depends(get_repository)],
) -> JSONResponse:
    """Exchange a single-use OAuth ticket and PKCE verifier for a Flutter session."""
    try:
        ticket_record = repository.consume_oauth_ticket(payload.ticket)
    except InvalidOrExpiredTicketError as exc:
        return _json_error(status.HTTP_400_BAD_REQUEST, "invalid_ticket", str(exc))

    try:
        validated_ticket_redirect = validate_app_redirect_uri(ticket_record.redirect_uri)
    except ValueError as exc:
        return _json_error(status.HTTP_400_BAD_REQUEST, "invalid_redirect_uri", str(exc))

    if payload.redirect_uri is not None and not hmac.compare_digest(
        payload.redirect_uri, validated_ticket_redirect
    ):
        return _json_error(
            status.HTTP_400_BAD_REQUEST,
            "redirect_uri_mismatch",
            "redirect_uri does not match authorization request",
        )

    if not verify_pkce_s256(payload.code_verifier, ticket_record.pkce_code_challenge):
        return _json_error(
            status.HTTP_400_BAD_REQUEST,
            "invalid_pkce",
            "PKCE code_verifier verification failed",
        )

    refresh_token = generate_refresh_token()
    session = repository.create_session(
        discord_user_id=ticket_record.discord_user_id,
        device_name=payload.device_name,
        device_id=payload.device_id,
        platform=payload.platform,
        refresh_token=refresh_token,
        ttl_days=SESSION_TTL_DAYS,
    )
    access_token, access_expires_at = create_access_token(
        session.session_id,
        session.discord_user_id,
        settings.orb_session_secret,
    )

    body = AuthTokensResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        access_expires_at=access_expires_at.astimezone(UTC).isoformat(),
        session_expires_at=session.session_expires_at.astimezone(UTC).isoformat(),
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=body.model_dump(),
        headers=_NO_STORE_HEADERS,
    )


@router.post("/api/v1/auth/refresh", response_model=AuthTokensResponse)
async def refresh_tokens(
    payload: AuthRefreshRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    repository: Annotated[Any, Depends(get_repository)],
) -> JSONResponse:
    """Rotate a valid refresh token and issue a fresh 15-minute access token."""
    new_refresh_token = generate_refresh_token()
    try:
        session = repository.rotate_refresh_token(payload.refresh_token, new_refresh_token)
    except RefreshTokenReusedError as exc:
        return _json_error(status.HTTP_401_UNAUTHORIZED, "token_reused", str(exc))
    except SessionExpiredError as exc:
        return _json_error(status.HTTP_401_UNAUTHORIZED, "session_expired", str(exc))
    except (SessionRevokedError, InvalidSessionError) as exc:
        return _json_error(status.HTTP_401_UNAUTHORIZED, "session_revoked", str(exc))

    access_token, access_expires_at = create_access_token(
        session.session_id,
        session.discord_user_id,
        settings.orb_session_secret,
    )
    body = AuthTokensResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        access_expires_at=access_expires_at.astimezone(UTC).isoformat(),
        session_expires_at=session.session_expires_at.astimezone(UTC).isoformat(),
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=body.model_dump(),
        headers=_NO_STORE_HEADERS,
    )


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token if token else None


def _find_active_session_id_by_refresh_token(repository: Any, refresh_token: str) -> str | None:
    candidate_hash = hash_token(refresh_token)
    for session in repository.list_active_sessions():
        if hmac.compare_digest(session.current_refresh_token_hash, candidate_hash):
            return str(session.session_id)
    return None


@router.post("/api/v1/auth/logout", response_model=AuthLogoutResponse)
async def logout(
    settings: Annotated[Settings, Depends(get_settings)],
    repository: Annotated[Any, Depends(get_repository)],
    authorization: Annotated[str | None, Header()] = None,
    payload: Annotated[AuthLogoutRequest | None, Body()] = None,
) -> JSONResponse:
    """Revoke the caller's Flutter session using Bearer access token or refresh token."""
    target_session_id: str | None = None

    bearer_token = _extract_bearer_token(authorization)
    if bearer_token is not None:
        try:
            claims = verify_access_token(bearer_token, settings.orb_session_secret)
            session = repository.get_session(claims.session_id)
            if session is not None:
                target_session_id = session.session_id
        except TokenError:
            target_session_id = None

    if target_session_id is None and payload is not None and payload.refresh_token:
        raw_refresh = payload.refresh_token.strip()
        if raw_refresh:
            target_session_id = _find_active_session_id_by_refresh_token(repository, raw_refresh)

    if target_session_id is None:
        return _json_error(
            status.HTTP_401_UNAUTHORIZED,
            "session_revoked",
            "Missing or invalid session credentials",
        )

    repository.revoke_session(target_session_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=AuthLogoutResponse(revoked=True).model_dump(),
        headers=_NO_STORE_HEADERS,
    )
