"""Build the backend Docker image and run container smoke tests."""

from __future__ import annotations

import http.client
import json
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

IMAGE_TAG = "discord-orb-backend:smoke"
BACKEND_DIR = Path(__file__).resolve().parent.parent
EXPECTED_MISSING_ENVS = {
    "ORB_PUBLIC_URL",
    "ORB_DISCORD_CLIENT_ID",
    "ORB_DISCORD_CLIENT_SECRET",
    "ORB_DISCORD_BOT_TOKEN",
    "ORB_SESSION_SECRET",
}
TEST_ENV = {
    "ORB_PUBLIC_URL": "https://orb.example.test",
    "ORB_DISCORD_CLIENT_ID": "smoke-test-client-id",
    "ORB_DISCORD_CLIENT_SECRET": "smoke-test-client-secret-value",
    "ORB_DISCORD_BOT_TOKEN": "smoke-test-bot-token-value",
    "ORB_SESSION_SECRET": "smoke-test-session-secret-value",
    "ORB_OPERATOR_DISCORD_IDS": "123456",
}
SECRET_VALUES = (
    TEST_ENV["ORB_DISCORD_CLIENT_SECRET"],
    TEST_ENV["ORB_DISCORD_BOT_TOKEN"],
    TEST_ENV["ORB_SESSION_SECRET"],
)


def _run_cmd(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=check,
        text=True,
        capture_output=True,
    )


def _build_image() -> None:
    print(f"Building Docker image {IMAGE_TAG} from {BACKEND_DIR}...")
    result = subprocess.run(
        ["docker", "build", "-t", IMAGE_TAG, str(BACKEND_DIR)],
        check=False,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker build failed with exit code {result.returncode}")


def _http_get(host: str, port: int, path: str) -> tuple[int, dict[str, str], str]:
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers, body
    finally:
        conn.close()


def _get_mapped_endpoint(container_name: str) -> tuple[str, int]:
    proc = _run_cmd(["docker", "port", container_name, "8080/tcp"])
    line = proc.stdout.strip().splitlines()[0].strip()
    host, port_str = line.rsplit(":", 1)
    if host in ("0.0.0.0", "[::]", "::"):
        host = "127.0.0.1"
    return host, int(port_str)


def _wait_until_ready(container_name: str, host: str, port: int, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_error: str | None = None
    while time.monotonic() < deadline:
        inspect_proc = _run_cmd(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
            check=False,
        )
        if inspect_proc.returncode != 0 or inspect_proc.stdout.strip() != "true":
            logs_proc = _run_cmd(["docker", "logs", container_name], check=False)
            raise RuntimeError(
                f"Container {container_name} exited unexpectedly.\n"
                f"stdout:\n{logs_proc.stdout}\nstderr:\n{logs_proc.stderr}"
            )
        try:
            status_code, _, _ = _http_get(host, port, "/healthz")
            if status_code == 200:
                return
            last_error = f"HTTP {status_code}"
        except OSError as exc:
            last_error = str(exc)
        time.sleep(0.25)

    logs_proc = _run_cmd(["docker", "logs", container_name], check=False)
    raise RuntimeError(
        f"Timed out waiting for {container_name} at {host}:{port}/healthz ({last_error}).\n"
        f"stdout:\n{logs_proc.stdout}\nstderr:\n{logs_proc.stderr}"
    )


@contextmanager
def _running_container(env: dict[str, str] | None = None) -> Iterator[tuple[str, str, int]]:
    container_name = f"discord-orb-smoke-{uuid.uuid4().hex[:8]}"
    with tempfile.TemporaryDirectory(prefix="discord-orb-smoke-") as temp_dir:
        cmd = [
            "docker",
            "run",
            "-d",
            "--name",
            container_name,
            "-p",
            "127.0.0.1:0:8080",
            "-v",
            f"{temp_dir}:/data",
        ]
        for key, value in (env or {}).items():
            cmd.extend(["-e", f"{key}={value}"])
        cmd.append(IMAGE_TAG)

        try:
            _run_cmd(cmd)
            host, port = _get_mapped_endpoint(container_name)
            _wait_until_ready(container_name, host, port)
            yield container_name, host, port
        finally:
            _run_cmd(["docker", "rm", "-f", container_name], check=False)


def _assert_no_secrets(text: str, source: str) -> None:
    for secret in SECRET_VALUES:
        assert secret not in text, f"Test secret leaked in {source}"


def _run_unconfigured_scenario() -> None:
    print("Running Scenario 1: unconfigured mode...")
    with _running_container() as (_, host, port):
        status, _, body = _http_get(host, port, "/healthz")
        assert status == 200, f"Expected 200 on /healthz, got {status}: {body}"
        health = json.loads(body)
        assert health.get("setup_required") is True, f"Expected setup_required=true, got {health}"
        missing = health.get("missing_env_names")
        assert isinstance(missing, list) and missing, f"Expected missing_env_names, got {health}"
        assert EXPECTED_MISSING_ENVS.issubset(set(missing)), (
            f"Missing expected env names in {missing}"
        )

        status, _, root_body = _http_get(host, port, "/")
        assert status == 200, f"Expected 200 on /, got {status}"
        assert "Setup Required" in root_body, "Expected 'Setup Required' on /"
        for env_name in missing:
            assert env_name in root_body, f"Expected env var name {env_name} on /"
        assert "<form" not in root_body.lower(), "Setup page must not render a <form>"
        _assert_no_secrets(root_body, "GET / (unconfigured)")

        status, _, channels_body = _http_get(host, port, "/api/v1/channels")
        assert status == 503, f"Expected 503 on /api/v1/channels, got {status}: {channels_body}"

        status, _, dashboard_body = _http_get(host, port, "/dashboard")
        assert status == 503, f"Expected 503 on /dashboard, got {status}: {dashboard_body}"
    print("Scenario 1 passed.")


def _run_configured_scenario() -> None:
    print("Running Scenario 2: test-configured mode...")
    with _running_container(TEST_ENV) as (container_name, host, port):
        responses_to_scan: list[tuple[str, str]] = []

        status, headers, body = _http_get(host, port, "/healthz")
        assert status == 200, f"Expected 200 on /healthz, got {status}: {body}"
        health = json.loads(body)
        assert health.get("setup_required") is False, f"Expected setup_required=false, got {health}"
        assert health.get("missing_env_names") == [], (
            f"Expected empty missing_env_names, got {health}"
        )
        responses_to_scan.append(("/healthz", body + json.dumps(headers)))

        status, headers, root_body = _http_get(host, port, "/")
        assert status == 200, f"Expected 200 on /, got {status}"
        assert "Setup Required" not in root_body, "Configured mode should not show Setup Required"
        responses_to_scan.append(("/", root_body + json.dumps(headers)))

        status, headers, channels_body = _http_get(host, port, "/api/v1/channels")
        assert status == 401, f"Expected 401 on /api/v1/channels, got {status}: {channels_body}"
        responses_to_scan.append(("/api/v1/channels", channels_body + json.dumps(headers)))

        status, headers, dashboard_body = _http_get(host, port, "/dashboard")
        assert status in (401, 403, 302), (
            f"Expected 401/403/302 on /dashboard, got {status}: {dashboard_body}"
        )
        if status == 302:
            assert headers.get("location"), "Expected Location header on 302 redirect"
        responses_to_scan.append(("/dashboard", dashboard_body + json.dumps(headers)))

        for route, content in responses_to_scan:
            _assert_no_secrets(content, f"GET {route}")

        logs_proc = _run_cmd(["docker", "logs", container_name])
        _assert_no_secrets(logs_proc.stdout + "\n" + logs_proc.stderr, "container logs")
    print("Scenario 2 passed.")


def main() -> int:
    _build_image()
    _run_unconfigured_scenario()
    _run_configured_scenario()
    print("All container smoke tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
