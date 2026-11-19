"""Session-bound HMAC CSRF token generation and verification for dashboard POST routes."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from fastapi import HTTPException, Request, status
from starlette.formparsers import MultiPartException

from ..config import Settings
from .operator_auth import OperatorSession

CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"
_CSRF_KEY_PURPOSE = b"orb-dashboard-csrf-key-v1"


def _derive_csrf_key(settings: Settings) -> bytes:
    if not settings.orb_session_secret:
        raise ValueError("orb_session_secret must not be empty")
    return hmac.new(
        settings.orb_session_secret.encode("utf-8"),
        _CSRF_KEY_PURPOSE,
        hashlib.sha256,
    ).digest()


def _sign_nonce(nonce: str, session: OperatorSession, settings: Settings) -> str:
    key = _derive_csrf_key(settings)
    message = f"{nonce}:{session.session_id}:{session.discord_user_id}:{session.issued_at}"
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def generate_csrf_token(session: OperatorSession, settings: Settings) -> str:
    """Generate a CSRF token cryptographically bound to the active operator session."""
    nonce = secrets.token_urlsafe(16)
    signature = _sign_nonce(nonce, session, settings)
    return f"{nonce}.{signature}"


def verify_csrf_token(
    token: str | None,
    session: OperatorSession,
    settings: Settings,
) -> bool:
    """Verify that a CSRF token is validly signed and bound to the operator session."""
    if not token or not settings.orb_session_secret or "." not in token:
        return False
    nonce, signature = token.split(".", 1)
    if not nonce or not signature:
        return False
    expected_signature = _sign_nonce(nonce, session, settings)
    return hmac.compare_digest(signature, expected_signature)


async def require_csrf_token(
    request: Request,
    session: OperatorSession,
    settings: Settings,
) -> None:
    """Validate the session-bound CSRF token from form body and/or X-CSRF-Token header."""
    header_token = request.headers.get(CSRF_HEADER_NAME)

    form_token: str | None = None
    try:
        form = await request.form()
        raw_value = form.get(CSRF_FORM_FIELD)
        if isinstance(raw_value, str):
            form_token = raw_value
    except (HTTPException, MultiPartException, ValueError, RuntimeError):
        form_token = None

    candidates: list[str] = []
    if form_token is not None:
        candidates.append(form_token)
    if header_token is not None:
        candidates.append(header_token)

    if not candidates:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing CSRF token",
        )

    for candidate in candidates:
        if not verify_csrf_token(candidate, session, settings):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid CSRF token",
            )
