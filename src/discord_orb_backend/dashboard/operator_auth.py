"""Operator web session authentication and Discord OAuth flow for the dashboard."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

from fastapi import Request, Response
from itsdangerous import BadSignature, URLSafeSerializer

from ..config import Settings

OPERATOR_SESSION_COOKIE_NAME = "orb_operator_session"
OPERATOR_OAUTH_STATE_COOKIE_NAME = "orb_operator_oauth_state"
OPERATOR_SESSION_TTL_SECONDS = 15 * 60
OAUTH_STATE_TTL_SECONDS = 5 * 60

DISCORD_AUTHORIZE_URL = "https://discord.com/oauth2/authorize"

_SESSION_SALT = "orb-operator-session-v1"
_OAUTH_STATE_SALT = "orb-operator-oauth-state-v1"


class OperatorAuthError(Exception):
    """Base error for operator authentication and authorization."""


class OperatorUnauthenticatedError(OperatorAuthError):
    """Raised when the operator session cookie is missing, invalid, or expired."""


class OperatorForbiddenError(OperatorAuthError):
    """Raised when the authenticated Discord user is not on the operator allowlist."""


@dataclass(frozen=True, slots=True)
class OperatorSession:
    """Verified short-lived operator dashboard session."""

    discord_user_id: str
    session_id: str
    issued_at: int
    expires_at: int


def _current_timestamp(now: float | None = None) -> int:
    return int(time.time() if now is None else now)


def _make_serializer(secret: str, salt: str) -> URLSafeSerializer:
    if not secret:
        raise ValueError("orb_session_secret must not be empty")
    return URLSafeSerializer(
        secret,
        salt=salt,
        signer_kwargs={"digest_method": hashlib.sha256},
    )


def get_dashboard_callback_url(settings: Settings) -> str:
    """Return the registered Discord OAuth callback URL for operator login."""
    base_url = settings.orb_public_url.rstrip("/")
    return f"{base_url}/dashboard/callback"


def build_discord_authorize_url(settings: Settings, state: str) -> str:
    """Build the Discord OAuth authorization URL with scope=identify."""
    query = urlencode(
        {
            "client_id": settings.orb_discord_client_id,
            "response_type": "code",
            "redirect_uri": get_dashboard_callback_url(settings),
            "scope": "identify",
            "state": state,
        }
    )
    return f"{DISCORD_AUTHORIZE_URL}?{query}"


def is_operator_allowed(discord_user_id: str, settings: Settings) -> bool:
    """Return True only when the allowlist is non-empty and contains discord_user_id."""
    if not discord_user_id:
        return False
    allowlist = settings.orb_operator_discord_ids
    if not allowlist:
        return False
    return discord_user_id in allowlist


def create_oauth_state_token(settings: Settings, *, now: float | None = None) -> str:
    """Create a signed short-lived OAuth state token for login CSRF protection."""
    issued_at = _current_timestamp(now)
    payload = {
        "nonce": secrets.token_urlsafe(24),
        "iat": issued_at,
        "exp": issued_at + OAUTH_STATE_TTL_SECONDS,
    }
    serializer = _make_serializer(settings.orb_session_secret, _OAUTH_STATE_SALT)
    return serializer.dumps(payload)


def verify_oauth_state_token(
    state: str | None,
    cookie_state: str | None,
    settings: Settings,
    *,
    now: float | None = None,
) -> bool:
    """Verify that the OAuth state matches the bound cookie, signature, and TTL."""
    if not state or not cookie_state or not settings.orb_session_secret:
        return False
    if not hmac.compare_digest(state, cookie_state):
        return False

    serializer = _make_serializer(settings.orb_session_secret, _OAUTH_STATE_SALT)
    try:
        payload = serializer.loads(state)
    except BadSignature:
        return False

    if not isinstance(payload, dict):
        return False

    issued_at = payload.get("iat")
    expires_at = payload.get("exp")
    nonce = payload.get("nonce")
    if (
        not isinstance(nonce, str)
        or not nonce
        or isinstance(issued_at, bool)
        or isinstance(expires_at, bool)
        or not isinstance(issued_at, int)
        or not isinstance(expires_at, int)
    ):
        return False

    if expires_at - issued_at != OAUTH_STATE_TTL_SECONDS:
        return False

    current_ts = _current_timestamp(now)
    return issued_at <= current_ts < expires_at


def create_operator_session_token(
    settings: Settings,
    discord_user_id: str,
    *,
    now: float | None = None,
) -> str:
    """Issue a signed 15-minute fixed-expiry operator session cookie token."""
    if not discord_user_id:
        raise ValueError("discord_user_id must not be empty")

    issued_at = _current_timestamp(now)
    payload = {
        "sub": discord_user_id,
        "sid": secrets.token_urlsafe(24),
        "iat": issued_at,
        "exp": issued_at + OPERATOR_SESSION_TTL_SECONDS,
    }
    serializer = _make_serializer(settings.orb_session_secret, _SESSION_SALT)
    return serializer.dumps(payload)


def verify_operator_session_token(
    token: str | None,
    settings: Settings,
    *,
    now: float | None = None,
) -> OperatorSession:
    """Verify operator cookie signature and fixed 15-minute expiration."""
    if not token or not settings.orb_session_secret:
        raise OperatorUnauthenticatedError("Operator sign-in required")

    serializer = _make_serializer(settings.orb_session_secret, _SESSION_SALT)
    try:
        payload = serializer.loads(token)
    except BadSignature as exc:
        raise OperatorUnauthenticatedError("Invalid operator session") from exc

    if not isinstance(payload, dict):
        raise OperatorUnauthenticatedError("Invalid operator session payload")

    discord_user_id = payload.get("sub")
    session_id = payload.get("sid")
    issued_at = payload.get("iat")
    expires_at = payload.get("exp")

    if (
        not isinstance(discord_user_id, str)
        or not discord_user_id
        or not isinstance(session_id, str)
        or not session_id
        or isinstance(issued_at, bool)
        or isinstance(expires_at, bool)
        or not isinstance(issued_at, int)
        or not isinstance(expires_at, int)
    ):
        raise OperatorUnauthenticatedError("Malformed operator session")

    if expires_at - issued_at != OPERATOR_SESSION_TTL_SECONDS:
        raise OperatorUnauthenticatedError("Invalid operator session lifetime")

    current_ts = _current_timestamp(now)
    if current_ts < issued_at or current_ts >= expires_at:
        raise OperatorUnauthenticatedError("Operator session has expired")

    return OperatorSession(
        discord_user_id=discord_user_id,
        session_id=session_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def authenticate_operator_request(
    request: Request,
    settings: Settings,
    *,
    now: float | None = None,
) -> OperatorSession:
    """Verify operator cookie session and re-check the allowlist on every request."""
    # Never accept Authorization: Bearer tokens from Flutter clients.
    token = request.cookies.get(OPERATOR_SESSION_COOKIE_NAME)
    session = verify_operator_session_token(token, settings, now=now)
    if not is_operator_allowed(session.discord_user_id, settings):
        raise OperatorForbiddenError("Discord account is not an authorized hosting operator")
    return session


def set_operator_session_cookie(response: Response, token: str) -> None:
    """Attach the signed HttpOnly Secure SameSite=Lax operator session cookie."""
    response.set_cookie(
        key=OPERATOR_SESSION_COOKIE_NAME,
        value=token,
        max_age=OPERATOR_SESSION_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/dashboard",
    )


def clear_operator_session_cookie(response: Response) -> None:
    """Clear the operator session cookie."""
    response.delete_cookie(
        key=OPERATOR_SESSION_COOKIE_NAME,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/dashboard",
    )


def set_oauth_state_cookie(response: Response, state: str) -> None:
    """Attach the short-lived OAuth state cookie."""
    response.set_cookie(
        key=OPERATOR_OAUTH_STATE_COOKIE_NAME,
        value=state,
        max_age=OAUTH_STATE_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/dashboard",
    )


def clear_oauth_state_cookie(response: Response) -> None:
    """Clear the short-lived OAuth state cookie."""
    response.delete_cookie(
        key=OPERATOR_OAUTH_STATE_COOKIE_NAME,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/dashboard",
    )
