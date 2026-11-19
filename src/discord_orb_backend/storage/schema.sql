CREATE TABLE IF NOT EXISTS oauth_tickets (
    ticket_hash TEXT PRIMARY KEY,
    discord_user_id TEXT NOT NULL,
    guilds_json TEXT NOT NULL,
    pkce_code_challenge TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

CREATE TABLE IF NOT EXISTS flutter_sessions (
    session_id TEXT PRIMARY KEY,
    discord_user_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    device_id TEXT NOT NULL,
    platform TEXT NOT NULL CHECK (platform IN ('android', 'macos', 'windows')),
    current_refresh_token_hash TEXT NOT NULL UNIQUE,
    previous_refresh_token_hash TEXT,
    created_at TEXT NOT NULL,
    session_expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_flutter_sessions_previous_refresh_token_hash
    ON flutter_sessions (previous_refresh_token_hash);

CREATE INDEX IF NOT EXISTS idx_flutter_sessions_discord_user_id
    ON flutter_sessions (discord_user_id);

CREATE TABLE IF NOT EXISTS instance_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    bot_enabled INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);
