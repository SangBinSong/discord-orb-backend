"""Token issuance, HMAC-SHA256 signing/verification, and PKCE S256 helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

ACCESS_TOKEN_TTL_SECONDS: int = 15 * 60
OAUTH_STATE_TTL_SECONDS: int = 10 * 60
OAUTH_TICKET_TTL_SECONDS: int = 120
SESSION_TTL_DAYS: int = 30

FLUTTER_ACCESS_TOKEN_TYPE: str = "flutter_access"
OAUTH_STATE_TOKEN_TYPE: str = "oauth_login_state"


class TokenError(Exception):
    """Base exception for signed token validation failures."""


class InvalidTokenError(TokenError):
    """Raised when a signed token is malformed, tampered, or wrong type."""


class TokenExpiredError(TokenError):
    """Raised when a signed token has passed its expiration timestamp."""


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    """Verified claims extracted from a Flutter client access token."""

    session_id: str
    discord_user_id: str
    exp: int
    typ: str


@dataclass(frozen=True, slots=True)
class OAuthStateClaims:
    """Verified claims extracted from a signed server OAuth state parameter."""

    redirect_uri: str
    code_challenge: str
    client_state: str
    exp: int
    typ: str


def _resolve_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(UTC)
    if now.tzinfo is None:
        return now.replace(tzinfo=UTC)
    return now.astimezone(UTC)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(encoded: str) -> bytes:
    if not encoded or not encoded.isascii():
        raise InvalidTokenError("Invalid base64url segment")
    padding = "=" * (-len(encoded) % 4)
    try:
        return base64.urlsafe_b64decode(encoded + padding)
    except ValueError as exc:
        raise InvalidTokenError("Malformed base64url segment") from exc


def _require_secret(secret: str) -> bytes:
    if not secret:
        raise ValueError("ORB_SESSION_SECRET must not be empty")
    return secret.encode("utf-8")


def _sign_payload(payload: dict[str, Any], secret: str) -> str:
    secret_bytes = _require_secret(secret)
    raw_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_segment = _b64url_encode(raw_json)
    signature = hmac.new(
        secret_bytes,
        payload_segment.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{payload_segment}.{_b64url_encode(signature)}"


def _verify_payload(
    token: str,
    secret: str,
    *,
    expected_typ: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not token or not isinstance(token, str) or "." not in token:
        raise InvalidTokenError("Malformed signed token")

    parts = token.split(".")
    if len(parts) != 2:
        raise InvalidTokenError("Malformed signed token structure")
    payload_segment, signature_segment = parts

    secret_bytes = _require_secret(secret)
    expected_sig = hmac.new(
        secret_bytes,
        payload_segment.encode("ascii"),
        hashlib.sha256,
    ).digest()
    presented_sig = _b64url_decode(signature_segment)
    if not hmac.compare_digest(expected_sig, presented_sig):
        raise InvalidTokenError("Invalid token signature")

    raw_payload = _b64url_decode(payload_segment)
    try:
        payload = json.loads(raw_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidTokenError("Invalid token JSON payload") from exc

    if not isinstance(payload, dict):
        raise InvalidTokenError("Token payload must be a JSON object")

    if payload.get("typ") != expected_typ:
        raise InvalidTokenError("Unexpected token type")

    exp = payload.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, int):
        raise InvalidTokenError("Token expiration claim is invalid")

    current_time = _resolve_now(now)
    if int(current_time.timestamp()) >= exp:
        raise TokenExpiredError("Token has expired")

    return payload


def generate_refresh_token() -> str:
    """Generate a high-entropy opaque refresh token."""
    return secrets.token_urlsafe(32)


def generate_oauth_ticket() -> str:
    """Generate a high-entropy single-use OAuth exchange ticket."""
    return secrets.token_urlsafe(32)


def create_access_token(
    session_id: str,
    discord_user_id: str,
    secret: str,
    *,
    ttl_seconds: int = ACCESS_TOKEN_TTL_SECONDS,
    now: datetime | None = None,
) -> tuple[str, datetime]:
    """Issue a 15-minute HMAC-SHA256 signed Flutter access token."""
    if not session_id or not discord_user_id:
        raise ValueError("session_id and discord_user_id must not be empty")
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")

    issued_at = _resolve_now(now).replace(microsecond=0)
    expires_at = issued_at + timedelta(seconds=ttl_seconds)
    exp = int(expires_at.timestamp())
    token = _sign_payload(
        {
            "typ": FLUTTER_ACCESS_TOKEN_TYPE,
            "session_id": session_id,
            "discord_user_id": discord_user_id,
            "exp": exp,
        },
        secret,
    )
    return token, expires_at


def verify_access_token(
    token: str,
    secret: str,
    *,
    now: datetime | None = None,
) -> AccessTokenClaims:
    """Verify a Flutter access token's signature, type, and expiration."""
    payload = _verify_payload(
        token,
        secret,
        expected_typ=FLUTTER_ACCESS_TOKEN_TYPE,
        now=now,
    )
    session_id = payload.get("session_id")
    discord_user_id = payload.get("discord_user_id")
    exp = payload["exp"]
    if (
        not isinstance(session_id, str)
        or not session_id
        or not isinstance(discord_user_id, str)
        or not discord_user_id
    ):
        raise InvalidTokenError("Access token is missing required claims")

    return AccessTokenClaims(
        session_id=session_id,
        discord_user_id=discord_user_id,
        exp=exp,
        typ=FLUTTER_ACCESS_TOKEN_TYPE,
    )


def create_oauth_state_token(
    redirect_uri: str,
    code_challenge: str,
    client_state: str,
    secret: str,
    *,
    ttl_seconds: int = OAUTH_STATE_TTL_SECONDS,
    now: datetime | None = None,
) -> str:
    """Issue a signed short-lived server OAuth state binding PKCE and redirect URI."""
    if not redirect_uri or not code_challenge or not client_state:
        raise ValueError("redirect_uri, code_challenge, and client_state must not be empty")
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")

    issued_at = _resolve_now(now).replace(microsecond=0)
    expires_at = issued_at + timedelta(seconds=ttl_seconds)
    return _sign_payload(
        {
            "typ": OAUTH_STATE_TOKEN_TYPE,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "client_state": client_state,
            "exp": int(expires_at.timestamp()),
        },
        secret,
    )


def verify_oauth_state_token(
    token: str,
    secret: str,
    *,
    now: datetime | None = None,
) -> OAuthStateClaims:
    """Verify a signed server OAuth state token and return its bound claims."""
    payload = _verify_payload(
        token,
        secret,
        expected_typ=OAUTH_STATE_TOKEN_TYPE,
        now=now,
    )
    redirect_uri = payload.get("redirect_uri")
    code_challenge = payload.get("code_challenge")
    client_state = payload.get("client_state")
    exp = payload["exp"]
    if (
        not isinstance(redirect_uri, str)
        or not redirect_uri
        or not isinstance(code_challenge, str)
        or not code_challenge
        or not isinstance(client_state, str)
        or not client_state
    ):
        raise InvalidTokenError("OAuth state token is missing required claims")

    return OAuthStateClaims(
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        client_state=client_state,
        exp=exp,
        typ=OAUTH_STATE_TOKEN_TYPE,
    )


def verify_pkce_s256(code_verifier: str, code_challenge: str) -> bool:
    """Verify an RFC 7636 S256 PKCE code_verifier against code_challenge."""
    if not code_verifier or not code_challenge:
        return False
    if not code_verifier.isascii() or not code_challenge.isascii():
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = _b64url_encode(digest)
    return hmac.compare_digest(computed, code_challenge)
