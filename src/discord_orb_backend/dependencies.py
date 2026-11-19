"""FastAPI dependency helpers for accessing app-level services."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request, status

from .config import Settings


def get_settings(request: Request) -> Settings:
    """Return the active Settings instance from application state."""
    settings = getattr(request.app.state, "settings", None)
    if settings is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Settings unavailable",
        )
    return settings


def get_repository(request: Request) -> Any:
    """Return the active storage repository from application state."""
    repository = getattr(request.app.state, "repository", None)
    if repository is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Repository unavailable",
        )
    return repository


def get_discord_client(request: Request) -> Any:
    """Return the active Discord client from application state."""
    discord_client = getattr(request.app.state, "discord_client", None)
    if discord_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Discord client unavailable",
        )
    return discord_client
