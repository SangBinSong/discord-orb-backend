# Discord Orb Backend

Self-hosted backend and operator dashboard for Discord Orb.

## HTTPS deployment

The Compose configuration publishes Caddy on ports 80 and 443. Caddy redirects HTTP to HTTPS and forwards HTTPS requests to the backend on the Docker network. The backend image must listen on container port 8080 and use `ORB_PUBLIC_URL` to build external URLs and its Discord OAuth callback. This repository currently contains the deployment configuration. It needs a backend image to run the API and web dashboard.

Copy [`.env.example`](.env.example) to `.env`. Set `ORB_DOMAIN` to the public hostname without a scheme or path, and `ORB_BACKEND_IMAGE` to the image to run. Put the backend's Discord credentials in `.env.backend` on the host. Docker Compose 2.24 or later supports leaving `.env.backend` absent while the backend serves its setup screen.

### Automatic certificate

Point the domain's DNS at the host and make ports 80 and 443 reachable. Caddy issues and renews a certificate and keeps it in `caddy_data`.

```sh
docker compose up -d
```

### Existing certificate

Set `ORB_TLS_CERT_FILE` to the host path of the PEM certificate chain for `ORB_DOMAIN` and `ORB_TLS_KEY_FILE` to the matching private key. Keep both files outside Git. Compose mounts them read-only into Caddy. Replace or renew these files through the certificate's issuer and recreate Caddy to load the updated pair.

```sh
docker compose -f compose.yaml -f compose.cert.yaml up -d
```

Register the exact callback URL under the same public HTTPS hostname in the Discord Developer Portal. Use that HTTPS base URL in the Flutter client. [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https) · [Caddy certificate files](https://caddyserver.com/docs/caddyfile/directives/tls)
