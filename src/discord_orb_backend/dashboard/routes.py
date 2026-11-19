"""FastAPI routes for the hosting operator dashboard (Jinja2 + HTMX)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..config import Settings
from ..dependencies import get_repository, get_settings
from ..discord import (
    DiscordApiError,
    DiscordBotUnavailableError,
    DiscordRateLimitError,
)
from .csrf import generate_csrf_token, require_csrf_token
from .operator_auth import (
    OPERATOR_OAUTH_STATE_COOKIE_NAME,
    OPERATOR_SESSION_COOKIE_NAME,
    OperatorForbiddenError,
    OperatorSession,
    OperatorUnauthenticatedError,
    authenticate_operator_request,
    build_discord_authorize_url,
    clear_oauth_state_cookie,
    clear_operator_session_cookie,
    create_oauth_state_token,
    create_operator_session_token,
    get_dashboard_callback_url,
    is_operator_allowed,
    set_oauth_state_cookie,
    set_operator_session_cookie,
    verify_oauth_state_token,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_JINJA_ENV = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(enabled_extensions=("html", "xml"), default_for_string=True),
)


def _render_html(
    template_name: str,
    *,
    status_code: int = status.HTTP_200_OK,
    headers: dict[str, str] | None = None,
    **context: Any,
) -> HTMLResponse:
    rendered = _JINJA_ENV.get_template(template_name).render(**context)
    merged_headers = {"Cache-Control": "no-store"}
    if headers:
        merged_headers.update(headers)
    return HTMLResponse(content=rendered, status_code=status_code, headers=merged_headers)


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request", "").strip().lower() == "true"


def _parse_bool_field(raw: Any) -> bool | None:
    if not isinstance(raw, str):
        return None
    normalized = raw.strip().lower()
    if normalized in {"true", "1", "on", "yes"}:
        return True
    if normalized in {"false", "0", "off", "no"}:
        return False
    return None


def _authenticate_or_error(
    request: Request,
    settings: Settings,
) -> tuple[OperatorSession | None, HTMLResponse | None]:
    try:
        return authenticate_operator_request(request, settings), None
    except OperatorUnauthenticatedError:
        response = _render_html(
            "auth_error.html",
            status_code=status.HTTP_401_UNAUTHORIZED,
            heading="Operator Sign-In Required",
            message=(
                "Sign in with an authorized hosting operator Discord account "
                "to access the dashboard."
            ),
            show_login=True,
        )
        if OPERATOR_SESSION_COOKIE_NAME in request.cookies:
            clear_operator_session_cookie(response)
        return None, response
    except OperatorForbiddenError:
        response = _render_html(
            "auth_error.html",
            status_code=status.HTTP_403_FORBIDDEN,
            heading="Access Denied",
            message="This Discord account is not authorized to manage this backend.",
            show_login=True,
        )
        return None, response


async def _build_bot_panel_context(
    settings: Settings,
    repository: Any,
    discord_client: Any,
) -> dict[str, Any]:
    bot_enabled = bool(repository.is_bot_enabled())
    if not bot_enabled:
        return {
            "bot_enabled": False,
            "bot_unavailable": False,
            "bot_error": None,
            "channel_statuses": [],
        }

    if not settings.bot_configured or discord_client is None:
        return {
            "bot_enabled": True,
            "bot_unavailable": True,
            "bot_error": None,
            "channel_statuses": [],
        }

    bot_unavailable = False
    bot_error: str | None = None
    channel_statuses: list[Any] = []
    try:
        channel_statuses = await discord_client.list_bot_channel_statuses()
    except DiscordBotUnavailableError:
        bot_unavailable = True
    except DiscordRateLimitError:
        bot_error = "Discord API rate limit reached while inspecting channels. Try again shortly."
    except DiscordApiError:
        bot_error = "Unable to fetch Discord channel permissions right now."

    return {
        "bot_enabled": True,
        "bot_unavailable": bot_unavailable,
        "bot_error": bot_error,
        "channel_statuses": channel_statuses,
    }


def _build_sessions_panel_context(repository: Any) -> dict[str, Any]:
    records = repository.list_active_sessions()
    sessions = [
        {
            "session_id": record.session_id,
            "device_name": record.device_name,
            "device_id": record.device_id,
            "platform": record.platform,
        }
        for record in records
    ]
    return {"sessions": sessions}


@router.get("/login")
async def dashboard_login(
    settings: Annotated[Settings, Depends(get_settings)],
) -> RedirectResponse:
    """Start the Discord OAuth authorization code flow for hosting operators."""
    state = create_oauth_state_token(settings)
    authorize_url = build_discord_authorize_url(settings, state)
    response = RedirectResponse(
        url=authorize_url,
        status_code=status.HTTP_302_FOUND,
        headers={"Cache-Control": "no-store"},
    )
    set_oauth_state_cookie(response, state)
    return response


@router.get("/callback")
async def dashboard_callback(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> Any:
    """Handle the Discord OAuth callback and issue a 15-minute operator cookie."""
    if error:
        response = _render_html(
            "auth_error.html",
            status_code=status.HTTP_403_FORBIDDEN,
            heading="Discord Sign-In Cancelled",
            message="Discord authorization was denied or cancelled.",
            show_login=True,
        )
        clear_oauth_state_cookie(response)
        return response

    if not code or not state:
        response = _render_html(
            "auth_error.html",
            status_code=status.HTTP_400_BAD_REQUEST,
            heading="Invalid OAuth Callback",
            message="Missing authorization code or state parameter.",
            show_login=True,
        )
        clear_oauth_state_cookie(response)
        return response

    cookie_state = request.cookies.get(OPERATOR_OAUTH_STATE_COOKIE_NAME)
    if not verify_oauth_state_token(state, cookie_state, settings):
        response = _render_html(
            "auth_error.html",
            status_code=status.HTTP_403_FORBIDDEN,
            heading="Invalid OAuth State",
            message="OAuth login state verification failed or expired. Please try again.",
            show_login=True,
        )
        clear_oauth_state_cookie(response)
        return response

    discord_client = getattr(request.app.state, "discord_client", None)
    if discord_client is None:
        response = _render_html(
            "auth_error.html",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            heading="Discord Client Unavailable",
            message="Discord OAuth client is currently unavailable.",
            show_login=True,
        )
        clear_oauth_state_cookie(response)
        return response

    try:
        user = await discord_client.exchange_code_for_user(
            code=code,
            redirect_uri=get_dashboard_callback_url(settings),
        )
    except DiscordRateLimitError as exc:
        retry_after = max(1, int(exc.retry_after))
        response = _render_html(
            "auth_error.html",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(retry_after)},
            heading="Discord Rate Limit",
            message="Discord API rate limit exceeded. Please try signing in again shortly.",
            show_login=True,
        )
        clear_oauth_state_cookie(response)
        return response
    except DiscordApiError as exc:
        status_code = (
            status.HTTP_401_UNAUTHORIZED
            if exc.status_code in (400, 401)
            else status.HTTP_502_BAD_GATEWAY
        )
        response = _render_html(
            "auth_error.html",
            status_code=status_code,
            heading="Discord Verification Failed",
            message="Could not verify your Discord account with Discord OAuth.",
            show_login=True,
        )
        clear_oauth_state_cookie(response)
        return response

    if not is_operator_allowed(user.id, settings):
        response = _render_html(
            "auth_error.html",
            status_code=status.HTTP_403_FORBIDDEN,
            heading="Access Denied",
            message="This Discord account is not listed in the hosting operator allowlist.",
            show_login=True,
        )
        clear_oauth_state_cookie(response)
        return response

    session_token = create_operator_session_token(settings, user.id)
    redirect_response = RedirectResponse(
        url="/dashboard",
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Cache-Control": "no-store"},
    )
    clear_oauth_state_cookie(redirect_response)
    set_operator_session_cookie(redirect_response, session_token)
    return redirect_response


@router.get("", response_class=HTMLResponse)
async def dashboard_home(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    repository: Annotated[Any, Depends(get_repository)],
) -> HTMLResponse:
    """Render the main operator dashboard page."""
    operator_session, error_response = _authenticate_or_error(request, settings)
    if error_response is not None or operator_session is None:
        assert error_response is not None
        return error_response

    csrf_token = generate_csrf_token(operator_session, settings)
    discord_client = getattr(request.app.state, "discord_client", None)
    bot_context = await _build_bot_panel_context(settings, repository, discord_client)
    sessions_context = _build_sessions_panel_context(repository)

    return _render_html(
        "dashboard.html",
        csrf_token=csrf_token,
        **bot_context,
        **sessions_context,
    )


@router.post("/sessions/{session_id}/revoke")
async def revoke_flutter_session(
    session_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    repository: Annotated[Any, Depends(get_repository)],
) -> Any:
    """Revoke a specific active Flutter session by its server session_id."""
    operator_session, error_response = _authenticate_or_error(request, settings)
    if error_response is not None or operator_session is None:
        assert error_response is not None
        return error_response

    await require_csrf_token(request, operator_session, settings)
    repository.revoke_session(session_id)

    if _is_htmx(request):
        csrf_token = generate_csrf_token(operator_session, settings)
        sessions_context = _build_sessions_panel_context(repository)
        return _render_html(
            "partials/sessions_panel.html",
            csrf_token=csrf_token,
            **sessions_context,
        )

    return RedirectResponse(
        url="/dashboard",
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Cache-Control": "no-store"},
    )


@router.post("/bot/toggle")
async def toggle_bot(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    repository: Annotated[Any, Depends(get_repository)],
) -> Any:
    """Toggle or set the instance-wide bot_enabled flag in persistent storage."""
    operator_session, error_response = _authenticate_or_error(request, settings)
    if error_response is not None or operator_session is None:
        assert error_response is not None
        return error_response

    await require_csrf_token(request, operator_session, settings)

    form = await request.form()
    explicit = _parse_bool_field(form.get("enabled"))
    if explicit is None:
        explicit = _parse_bool_field(form.get("bot_enabled"))

    target_enabled = explicit if explicit is not None else not bool(repository.is_bot_enabled())
    repository.set_bot_enabled(target_enabled)

    if _is_htmx(request):
        csrf_token = generate_csrf_token(operator_session, settings)
        discord_client = getattr(request.app.state, "discord_client", None)
        bot_context = await _build_bot_panel_context(settings, repository, discord_client)
        return _render_html(
            "partials/bot_panel.html",
            csrf_token=csrf_token,
            **bot_context,
        )

    return RedirectResponse(
        url="/dashboard",
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Cache-Control": "no-store"},
    )


@router.post("/logout")
async def dashboard_logout(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Any:
    """Clear the operator cookie session after CSRF validation."""
    operator_session, error_response = _authenticate_or_error(request, settings)
    if error_response is not None or operator_session is None:
        assert error_response is not None
        return error_response

    await require_csrf_token(request, operator_session, settings)

    if _is_htmx(request):
        response: HTMLResponse | RedirectResponse = HTMLResponse(
            content="",
            status_code=status.HTTP_200_OK,
            headers={"HX-Redirect": "/dashboard", "Cache-Control": "no-store"},
        )
    else:
        response = RedirectResponse(
            url="/dashboard",
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Cache-Control": "no-store"},
        )
    clear_operator_session_cookie(response)
    return response
