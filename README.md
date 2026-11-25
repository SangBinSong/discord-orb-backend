# Discord Orb Backend

Self-hosted backend and operator dashboard for Discord Orb.

## Architecture & Runtime

- **Stack**: Python 3.12 (`uv`), `FastAPI`, `httpx`, `Jinja2` + `HTMX`, and built-in `sqlite3` (WAL mode).
- **Port**: Container listens on HTTP port `8080` behind either the bundled Caddy HTTPS reverse proxy (`compose.yaml`) or an external HTTPS reverse proxy (`compose.external-proxy.yaml`).
- **Persistence**: Stores single-use OAuth exchange tickets, active Flutter sessions (with rotating refresh token hashes), and the instance-wide bot enabled/disabled flag in `ORB_DB_PATH` (default `/data/orb.db`), mounted on the `orb_data` Docker volume across container recreations.
- **Unconfigured boot mode**: Starts cleanly with all deployment environment variables unset. `GET /healthz` and `GET /` remain reachable (showing only the names of missing variables, with no input forms or secret values), while `/api/*`, `/auth/*`, and `/dashboard/*` return `503 Setup required` until OAuth settings are provided.

## Environment Variables

Configure Docker Compose settings in `.env` (see [`.env.example`](.env.example)) and backend secrets in an untracked `.env.backend` file on the host (copy from [`.env.backend.example`](.env.backend.example)).

### `.env` (Docker Compose)

- `ORB_DOMAIN`: Public HTTPS hostname without scheme or path (for example, `orb.example.com`). Compose derives `ORB_PUBLIC_URL=https://${ORB_DOMAIN}` for the backend.
- `ORB_BACKEND_IMAGE`: Container image to run (for example, `ghcr.io/sangbinsong/discord-orb-backend:<version>` or a locally built tag).
- `ORB_TLS_CERT_FILE` / `ORB_TLS_KEY_FILE`: Optional host paths to a PEM certificate chain and matching private key when using `compose.cert.yaml` with `compose.yaml`.
- `ORB_BIND_HOST`: Optional host bind address when using `compose.external-proxy.yaml` (default `127.0.0.1`, keeping plaintext HTTP off public interfaces).
- `ORB_BIND_PORT`: Optional host port mapped to container port `8080` when using `compose.external-proxy.yaml` (default `8080`).

### `.env.backend` (Backend Runtime)

| Variable | Required | Description |
| --- | --- | --- |
| `ORB_DISCORD_CLIENT_ID` | Yes | Discord application OAuth2 client ID |
| `ORB_DISCORD_CLIENT_SECRET` | Yes | Discord application OAuth2 client secret |
| `ORB_DISCORD_BOT_TOKEN` | Yes (for previews) | Raw Discord bot token without the `Bot ` prefix (the backend sends `Authorization: Bot <token>` automatically); if omitted, OAuth and `/dashboard` stay reachable while previews return `503` |
| `ORB_SESSION_SECRET` | Yes | Signing secret for OAuth state, Flutter 15-minute access tokens, and operator cookies |
| `ORB_OPERATOR_DISCORD_IDS` | Recommended | Comma-separated Discord user IDs allowed to access `/dashboard` (empty denies all users) |
| `ORB_DB_PATH` | Optional | SQLite database path inside container (default `/data/orb.db` in the Compose files) |
| `ORB_PUBLIC_URL` | Yes | Public HTTPS base URL (auto-set by the Compose files from `ORB_DOMAIN`) |

Copy [`.env.backend.example`](.env.backend.example) to `.env.backend` and replace the placeholders (keep real values outside Git):

```sh
ORB_DISCORD_CLIENT_ID=replace-with-client-id
ORB_DISCORD_CLIENT_SECRET=replace-with-client-secret
ORB_DISCORD_BOT_TOKEN=replace-with-bot-token
ORB_SESSION_SECRET=replace-with-long-random-secret
ORB_OPERATOR_DISCORD_IDS=123456789012345678
```

## Discord Developer Portal Setup

1. Create a Discord application and add a Bot user. Invite the bot to participating servers with permission to view intended channels and read message history.
2. Under **OAuth2 -> Redirects**, register both exact HTTPS callback URLs under `ORB_DOMAIN`:
   - Flutter client callback: `https://<ORB_DOMAIN>/auth/discord/callback`
   - Operator dashboard callback: `https://<ORB_DOMAIN>/dashboard/callback`
3. Keep `ORB_DISCORD_CLIENT_SECRET`, `ORB_DISCORD_BOT_TOKEN`, and `ORB_SESSION_SECRET` only on the host in `.env.backend` (never in Dockerfiles, build args, CI logs, or Git).

## HTTPS Deployment

Copy [`.env.example`](.env.example) to `.env`, copy [`.env.backend.example`](.env.backend.example) to `.env.backend` on the host (optional if booting in unconfigured setup mode with Docker Compose 2.24+), then choose one of the two Docker Compose deployment options below.

### Option 1: Bundled Caddy reverse proxy (`compose.yaml`)

Use `compose.yaml` when this host does not already run a reverse proxy. It runs both `backend` and `caddy`, publishes ports `80` and `443`, redirects HTTP to HTTPS, and forwards HTTPS requests to the backend over the internal Docker network.

#### Automatic certificate

Point the domain's DNS at the host and make ports `80` and `443` reachable. Caddy issues and renews a certificate and keeps it in `caddy_data`.

```sh
docker compose up -d
```

#### Existing certificate

Set `ORB_TLS_CERT_FILE` to the host path of the PEM certificate chain for `ORB_DOMAIN` and `ORB_TLS_KEY_FILE` to the matching private key. Keep both files outside Git. Compose mounts them read-only into Caddy. Replace or renew these files through the certificate's issuer and recreate Caddy to load the updated pair.

```sh
docker compose -f compose.yaml -f compose.cert.yaml up -d
```

[Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https) · [Caddy certificate files](https://caddyserver.com/docs/caddyfile/directives/tls)

### Option 2: External reverse proxy (`compose.external-proxy.yaml`)

Use `compose.external-proxy.yaml` when you already run an HTTPS reverse proxy (such as Nginx, Nginx Proxy Manager, Traefik, a separate Caddy instance, or Cloudflare Tunnel). This Compose file runs only the `backend` service and the `orb_data` volume (omitting `caddy` and `caddy_data`).

```sh
docker compose -f compose.external-proxy.yaml up -d
```

- **Localhost-only binding by default**: Container port `8080` is published to `127.0.0.1:8080` by default to avoid exposing plaintext HTTP on public network interfaces. Set `ORB_BIND_HOST` and/or `ORB_BIND_PORT` in `.env` if your proxy needs a different bind address or host port.
- **Required reverse proxy configuration**: Your external reverse proxy must terminate HTTPS for `ORB_DOMAIN`, forward traffic to `http://<ORB_BIND_HOST>:<ORB_BIND_PORT>` (default `http://127.0.0.1:8080`), and pass the following headers so redirects and secure cookies work properly:
  - `Host`
  - `X-Forwarded-Proto: https`
  - `X-Forwarded-For`

### Updating or Rotating Secrets

Update `.env` or `.env.backend` (or bump `ORB_BACKEND_IMAGE`), then pull and recreate the container. Persistent SQLite data in `orb_data` is preserved:

```sh
# Bundled Caddy (compose.yaml)
docker compose pull
docker compose up -d

# External reverse proxy (compose.external-proxy.yaml)
docker compose -f compose.external-proxy.yaml pull
docker compose -f compose.external-proxy.yaml up -d
```

## Operator Dashboard (`/dashboard`)

- Open `https://<ORB_DOMAIN>/dashboard` in a browser and sign in with Discord OAuth. Only Discord user IDs listed in `ORB_OPERATOR_DISCORD_IDS` are admitted (checked on every request; 15-minute fixed HTTP-only cookie session).
- **Bot & Channel Status**: Lists servers and standard non-NSFW text channels visible to the bot, showing `VIEW_CHANNEL` and `READ_MESSAGE_HISTORY` status (marking channels lacking history permission as `unreadable`).
- **Bot Preview Toggle**: Disables or enables bot-backed previews instance-wide (`POST /dashboard/bot/toggle` with CSRF protection). When disabled, preview API endpoints return `503` without calling Discord, while `/dashboard` remains accessible. State persists in SQLite across container restarts.
- **Active Flutter Sessions**: Lists `device_name`, `device_id`, and `platform` for active sessions and supports CSRF-protected per-session force revocation (`POST /dashboard/sessions/{session_id}/revoke`), immediately rejecting both access and refresh tokens.

## Local Development & Verification

```sh
uv sync
uv run ruff check
uv run ruff format --check
uv run pytest
python3 scripts/container_smoke_test.py
```

On pull requests and pushes to `main`, [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `ruff`, `pytest`, and `scripts/container_smoke_test.py`. Pushing a `v*` tag builds and publishes multi-architecture (`linux/amd64`, `linux/arm64`) images to `ghcr.io/sangbinsong/discord-orb-backend`.
