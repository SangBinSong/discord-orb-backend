"""Application configuration loaded from environment variables."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

REQUIRED_ENV_NAMES: tuple[str, ...] = (
    "ORB_PUBLIC_URL",
    "ORB_DB_PATH",
    "ORB_DISCORD_CLIENT_ID",
    "ORB_DISCORD_CLIENT_SECRET",
    "ORB_DISCORD_BOT_TOKEN",
    "ORB_SESSION_SECRET",
)

OAUTH_REQUIRED_ENV_NAMES: tuple[str, ...] = (
    "ORB_PUBLIC_URL",
    "ORB_DISCORD_CLIENT_ID",
    "ORB_DISCORD_CLIENT_SECRET",
    "ORB_SESSION_SECRET",
)


class Settings(BaseSettings):
    """Runtime settings for the Discord Orb backend."""

    model_config = SettingsConfigDict(extra="ignore")

    orb_public_url: str = ""
    orb_db_path: str = "/data/orb.db"
    orb_discord_client_id: str = ""
    orb_discord_client_secret: str = ""
    orb_discord_bot_token: str = ""
    orb_operator_discord_ids: Annotated[tuple[str, ...], NoDecode] = ()
    orb_session_secret: str = ""

    @field_validator(
        "orb_public_url",
        "orb_db_path",
        "orb_discord_client_id",
        "orb_discord_client_secret",
        "orb_discord_bot_token",
        "orb_session_secret",
        mode="before",
    )
    @classmethod
    def _strip_string(cls, value: Any) -> str:
        if value is None:
            return ""
        return str(value).strip()

    @field_validator("orb_operator_discord_ids", mode="before")
    @classmethod
    def _parse_operator_ids(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split(",") if item.strip())
        if isinstance(value, (list, tuple, set, frozenset)):
            return tuple(str(item).strip() for item in value if str(item).strip())
        raise ValueError("Invalid ORB_OPERATOR_DISCORD_IDS value")

    @classmethod
    def from_env(cls) -> Settings:
        """Load settings from process environment variables."""
        return cls()

    def _env_value(self, env_name: str) -> str:
        return getattr(self, env_name.lower(), "")

    @property
    def missing_env_names(self) -> list[str]:
        """Return required environment variable names that are missing or empty."""
        return [name for name in REQUIRED_ENV_NAMES if not self._env_value(name)]

    @property
    def oauth_configured(self) -> bool:
        """Whether all required OAuth and session settings are present."""
        return all(bool(self._env_value(name)) for name in OAUTH_REQUIRED_ENV_NAMES)

    @property
    def bot_configured(self) -> bool:
        """Whether the Discord bot token is configured."""
        return bool(self.orb_discord_bot_token)

    @property
    def setup_required(self) -> bool:
        """Whether any required environment variable is missing."""
        return bool(self.missing_env_names)
