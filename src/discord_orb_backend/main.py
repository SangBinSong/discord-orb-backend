"""FastAPI application factory, lifecycle hooks, and bootstrap endpoints."""

from __future__ import annotations

import html
import inspect
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.responses import HTMLResponse, JSONResponse

from .api import router as api_router
from .config import Settings
from .dashboard import router as dashboard_router
from .discord import DiscordClient
from .storage import Repository

_GUARDED_PREFIXES: tuple[str, ...] = ("/api", "/auth", "/dashboard")


def _is_guarded_path(path: str) -> bool:
    return any(path == prefix or path.startswith(f"{prefix}/") for prefix in _GUARDED_PREFIXES)


async def _close_resource(resource: Any) -> None:
    """Close a lifecycle-managed resource, preferring async aclose()."""
    if resource is None:
        return
    aclose = getattr(resource, "aclose", None)
    if callable(aclose):
        result = aclose()
        if inspect.isawaitable(result):
            await result
        return
    close = getattr(resource, "close", None)
    if callable(close):
        result = close()
        if inspect.isawaitable(result):
            await result


def _render_setup_html(missing_env_names: list[str]) -> str:
    items = "".join(f"<li><code>{html.escape(name)}</code></li>" for name in missing_env_names)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Discord Orb Backend - Setup Required</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; margin: 2rem auto; max-width: 640px; padding: 0 1rem; color: #1f2937; }}
    h1 {{ font-size: 1.5rem; margin-bottom: 0.75rem; }}
    p {{ line-height: 1.5; }}
    ul {{ background: #f3f4f6; padding: 1rem 1rem 1rem 2rem; border-radius: 0.5rem; }}
    code {{ font-family: ui-monospace, SFMono-Regular, monospace; }}
  </style>
</head>
<body>
  <h1>Setup Required</h1>
  <p>Discord Orb Backend is running, but required environment variables are not configured yet.</p>
  <p>Configure the following environment variables on the host and restart the service:</p>
  <ul>
    {items}
  </ul>
</body>
</html>
"""


def _render_status_html(settings: Settings) -> str:
    bot_status = "configured" if settings.bot_configured else "not configured"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Discord Orb Backend</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; margin: 2rem auto; max-width: 640px; padding: 0 1rem; color: #1f2937; }}
    h1 {{ font-size: 1.5rem; margin-bottom: 0.75rem; }}
    p {{ line-height: 1.5; }}
    code {{ font-family: ui-monospace, SFMono-Regular, monospace; }}
  </style>
</head>
<body>
  <h1>Discord Orb Backend</h1>
  <p>Status: <strong>Running</strong> (OAuth configured, bot token {html.escape(bot_status)}).</p>
  <p>Check <code>/healthz</code> for machine-readable health status.</p>
</body>
</html>
"""


def create_app(
    settings: Settings | None = None,
    *,
    repository: Any = None,
    discord_client: Any = None,
) -> FastAPI:
    """Create and configure the FastAPI application instance."""
    resolved_settings = settings if settings is not None else Settings.from_env()

    @asynccontextmanager
    async def lifespan(app_instance: FastAPI) -> AsyncIterator[None]:
        owns_repository = False
        owns_discord_client = False

        # Skip DB/Discord wiring in unconfigured mode so boot works without /data write access.
        if resolved_settings.oauth_configured:
            if app_instance.state.repository is None:
                db_path = resolved_settings.orb_db_path
                if db_path and db_path != ":memory:":
                    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
                app_instance.state.repository = Repository(db_path)
                owns_repository = True

            if app_instance.state.discord_client is None:
                app_instance.state.discord_client = DiscordClient(settings=resolved_settings)
                owns_discord_client = True

        try:
            yield
        finally:
            if owns_discord_client:
                await _close_resource(app_instance.state.discord_client)
                app_instance.state.discord_client = None
            if owns_repository:
                await _close_resource(app_instance.state.repository)
                app_instance.state.repository = None

    application = FastAPI(title="Discord Orb Backend", lifespan=lifespan)
    application.state.settings = resolved_settings
    application.state.repository = repository
    application.state.discord_client = discord_client

    @application.middleware("http")
    async def require_oauth_configuration(request: Request, call_next: Any) -> Any:
        active_settings: Settings = request.app.state.settings
        if not active_settings.oauth_configured and _is_guarded_path(request.url.path):
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={
                    "detail": "Setup required",
                    "setup_required": True,
                    "missing_env_names": active_settings.missing_env_names,
                },
            )
        return await call_next(request)

    @application.get("/healthz")
    async def healthz(request: Request) -> JSONResponse:
        active_settings: Settings = request.app.state.settings
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "ok",
                "setup_required": active_settings.setup_required,
                "missing_env_names": active_settings.missing_env_names,
            },
        )

    @application.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        active_settings: Settings = request.app.state.settings
        if not active_settings.oauth_configured:
            return HTMLResponse(
                content=_render_setup_html(active_settings.missing_env_names),
                status_code=status.HTTP_200_OK,
            )
        return HTMLResponse(
            content=_render_status_html(active_settings),
            status_code=status.HTTP_200_OK,
        )

    application.include_router(api_router)
    application.include_router(dashboard_router)

    return application


app = create_app()
