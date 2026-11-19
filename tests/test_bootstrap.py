"""Bootstrap tests for configuration, dependencies, healthcheck, and setup screen."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from fastapi.testclient import TestClient

from discord_orb_backend.config import REQUIRED_ENV_NAMES, Settings
from discord_orb_backend.dependencies import (
    get_discord_client,
    get_repository,
    get_settings,
)
from discord_orb_backend.main import create_app


def _clear_orb_env(monkeypatch) -> None:
    for name in (
        *REQUIRED_ENV_NAMES,
        "ORB_OPERATOR_DISCORD_IDS",
    ):
        monkeypatch.delenv(name, raising=False)


def test_settings_loads_with_empty_environment(monkeypatch) -> None:
    _clear_orb_env(monkeypatch)
    settings = Settings.from_env()

    assert settings.orb_public_url == ""
    assert settings.orb_db_path == "/data/orb.db"
    assert settings.orb_discord_client_id == ""
    assert settings.orb_discord_client_secret == ""
    assert settings.orb_discord_bot_token == ""
    assert settings.orb_operator_discord_ids == ()
    assert settings.orb_session_secret == ""
    assert settings.oauth_configured is False
    assert settings.bot_configured is False
    assert settings.setup_required is True
    assert settings.missing_env_names == [
        "ORB_PUBLIC_URL",
        "ORB_DISCORD_CLIENT_ID",
        "ORB_DISCORD_CLIENT_SECRET",
        "ORB_DISCORD_BOT_TOKEN",
        "ORB_SESSION_SECRET",
    ]
    assert "ORB_OPERATOR_DISCORD_IDS" not in settings.missing_env_names


def test_settings_empty_db_path_is_reported_missing(monkeypatch) -> None:
    _clear_orb_env(monkeypatch)
    monkeypatch.setenv("ORB_DB_PATH", "   ")
    settings = Settings.from_env()

    assert "ORB_DB_PATH" in settings.missing_env_names
    assert settings.setup_required is True


def test_settings_oauth_only_without_bot_token(monkeypatch) -> None:
    _clear_orb_env(monkeypatch)
    monkeypatch.setenv("ORB_PUBLIC_URL", "https://orb.example.com")
    monkeypatch.setenv("ORB_DISCORD_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("ORB_DISCORD_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("ORB_SESSION_SECRET", "test-session-secret")

    settings = Settings.from_env()

    assert settings.oauth_configured is True
    assert settings.bot_configured is False
    assert settings.setup_required is True
    assert settings.missing_env_names == ["ORB_DISCORD_BOT_TOKEN"]


def test_settings_fully_configured_with_operator_ids(monkeypatch) -> None:
    _clear_orb_env(monkeypatch)
    monkeypatch.setenv("ORB_PUBLIC_URL", "https://orb.example.com")
    monkeypatch.setenv("ORB_DB_PATH", "/tmp/orb-test.db")
    monkeypatch.setenv("ORB_DISCORD_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("ORB_DISCORD_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("ORB_DISCORD_BOT_TOKEN", "test-bot-token")
    monkeypatch.setenv("ORB_OPERATOR_DISCORD_IDS", "111111, 222222 , 333333")
    monkeypatch.setenv("ORB_SESSION_SECRET", "test-session-secret")

    settings = Settings.from_env()

    assert settings.oauth_configured is True
    assert settings.bot_configured is True
    assert settings.setup_required is False
    assert settings.missing_env_names == []
    assert settings.orb_operator_discord_ids == ("111111", "222222", "333333")


def test_unconfigured_app_healthz_setup_page_and_guards(monkeypatch) -> None:
    _clear_orb_env(monkeypatch)
    monkeypatch.setenv("ORB_DISCORD_BOT_TOKEN", "secret-bot-token-value")
    settings = Settings.from_env()
    app = create_app(settings)

    with TestClient(app) as client:
        health = client.get("/healthz")
        assert health.status_code == 200
        assert health.json() == {
            "status": "ok",
            "setup_required": True,
            "missing_env_names": [
                "ORB_PUBLIC_URL",
                "ORB_DISCORD_CLIENT_ID",
                "ORB_DISCORD_CLIENT_SECRET",
                "ORB_SESSION_SECRET",
            ],
        }

        root = client.get("/")
        assert root.status_code == 200
        assert "text/html" in root.headers["content-type"]
        body = root.text
        for env_name in settings.missing_env_names:
            assert env_name in body
        assert "<form" not in body.lower()
        assert "<input" not in body.lower()
        assert "secret-bot-token-value" not in body

        for path in ("/api/v1/channels", "/auth/discord/login", "/dashboard"):
            blocked = client.get(path)
            assert blocked.status_code == 503
            payload = blocked.json()
            assert payload == {
                "detail": "Setup required",
                "setup_required": True,
                "missing_env_names": settings.missing_env_names,
            }
            assert "secret-bot-token-value" not in blocked.text


def test_configured_app_healthz_root_and_dependencies() -> None:
    settings = Settings(
        orb_public_url="https://orb.example.com",
        orb_db_path="/tmp/test.db",
        orb_discord_client_id="test-client-id",
        orb_discord_client_secret="test-client-secret",
        orb_discord_bot_token="test-bot-token",
        orb_operator_discord_ids=("12345",),
        orb_session_secret="test-session-secret",
    )
    fake_repo = {"kind": "repo"}
    fake_discord = {"kind": "discord"}
    app = create_app(settings, repository=fake_repo, discord_client=fake_discord)

    @app.get("/_test/deps")
    def _check_deps(
        dep_settings: Annotated[Settings, Depends(get_settings)],
        dep_repo: Annotated[dict[str, str], Depends(get_repository)],
        dep_discord: Annotated[dict[str, str], Depends(get_discord_client)],
    ) -> dict[str, object]:
        return {
            "public_url": dep_settings.orb_public_url,
            "repo": dep_repo,
            "discord": dep_discord,
        }

    with TestClient(app) as client:
        health = client.get("/healthz")
        assert health.status_code == 200
        assert health.json() == {
            "status": "ok",
            "setup_required": False,
            "missing_env_names": [],
        }

        root = client.get("/")
        assert root.status_code == 200
        assert "text/html" in root.headers["content-type"]
        assert "test-client-secret" not in root.text
        assert "test-bot-token" not in root.text
        assert "test-session-secret" not in root.text

        deps = client.get("/_test/deps")
        assert deps.status_code == 200
        assert deps.json() == {
            "public_url": "https://orb.example.com",
            "repo": {"kind": "repo"},
            "discord": {"kind": "discord"},
        }


def test_dependencies_return_503_when_missing(tmp_path) -> None:
    settings = Settings(
        orb_public_url="https://orb.example.com",
        orb_db_path=str(tmp_path / "orb.db"),
        orb_discord_client_id="test-client-id",
        orb_discord_client_secret="test-client-secret",
        orb_session_secret="test-session-secret",
    )
    app = create_app(settings)

    @app.get("/_test/repo")
    def _check_repo(_repo: Annotated[object, Depends(get_repository)]) -> dict[str, str]:
        return {"ok": "true"}

    @app.get("/_test/discord")
    def _check_discord(
        _client: Annotated[object, Depends(get_discord_client)],
    ) -> dict[str, str]:
        return {"ok": "true"}

    with TestClient(app) as client:
        assert app.state.repository is not None
        assert app.state.discord_client is not None

        app.state.repository = None
        app.state.discord_client = None

        assert client.get("/_test/repo").status_code == 503
        assert client.get("/_test/discord").status_code == 503
