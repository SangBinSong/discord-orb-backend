"""Tests for Discord Gateway v10, in-memory broker, SSE streaming, and non-persistence."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient
from websockets.exceptions import ConnectionClosedError
from websockets.frames import Close

from discord_orb_backend.api.tokens import create_access_token
from discord_orb_backend.config import Settings
from discord_orb_backend.discord import (
    MINIMAL_GATEWAY_INTENTS,
    REQUIRED_PERMISSIONS,
    VIEW_CHANNEL,
    ChannelEventBroker,
    ChannelStreamEvent,
    DiscordClient,
    DiscordGatewayClient,
    normalize_gateway_dispatch,
    resolve_author_avatar_url,
    resolve_guild_icon_url,
)
from discord_orb_backend.main import create_app
from discord_orb_backend.storage import OrbRepository

TEST_SECRET = "sse-test-session-secret-0123456789"


class FakeWebSocket:
    """In-memory async WebSocket fake for deterministic Discord Gateway v10 tests."""

    def __init__(
        self,
        incoming_frames: list[dict[str, Any] | str] | None = None,
        *,
        close_error: BaseException | None = None,
    ) -> None:
        self._incoming: asyncio.Queue[str | BaseException | None] = asyncio.Queue()
        for frame in incoming_frames or []:
            self.push(frame)
        self._close_error = close_error
        self.sent: list[dict[str, Any]] = []
        self.sent_event = asyncio.Event()
        self.closed = False
        self.close_codes: list[int] = []

    def push(self, frame: dict[str, Any] | str) -> None:
        payload = json.dumps(frame) if isinstance(frame, dict) else frame
        self._incoming.put_nowait(payload)

    def end(self, error: BaseException | None = None) -> None:
        self._incoming.put_nowait(error if error is not None else self._close_error)

    async def send(self, payload: str) -> None:
        self.sent.append(json.loads(payload))
        self.sent_event.set()

    async def wait_for_sent_count(self, count: int, timeout: float = 2.0) -> None:
        deadline = asyncio.get_running_loop().time() + timeout
        while len(self.sent) < count:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timed out waiting for {count} sent frames (got {len(self.sent)})"
                )
            self.sent_event.clear()
            await asyncio.wait_for(self.sent_event.wait(), timeout=remaining)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = True
        self.close_codes.append(code)
        self._incoming.put_nowait(None)

    def __aiter__(self) -> AsyncIterator[str]:
        return self._iterate()

    async def _iterate(self) -> AsyncIterator[str]:
        while True:
            item = await self._incoming.get()
            if item is None:
                return
            if isinstance(item, BaseException):
                raise item
            yield item


def _make_settings(
    tmp_path: Path,
    *,
    bot_token: str = "synthetic-bot-token-secret-xyz",
) -> Settings:
    return Settings(
        orb_public_url="https://orb.example.com",
        orb_db_path=str(tmp_path / "orb-sse.db"),
        orb_discord_client_id="test-client-id",
        orb_discord_client_secret="test-client-secret",
        orb_discord_bot_token=bot_token,
        orb_operator_discord_ids=("op-1",),
        orb_session_secret=TEST_SECRET,
    )


def _build_discord_mock(
    *,
    perms: dict[tuple[str, str], int | None] | None = None,
    rate_limit_path: str | None = None,
) -> httpx.MockTransport:
    resolved_perms = (
        perms
        if perms is not None
        else {
            ("ch-1", "bot-1"): REQUIRED_PERMISSIONS,
            ("ch-1", "user-1"): REQUIRED_PERMISSIONS,
            ("ch-denied", "bot-1"): REQUIRED_PERMISSIONS,
            ("ch-denied", "user-1"): VIEW_CHANNEL,
            ("ch-bot-bad", "bot-1"): VIEW_CHANNEL,
            ("ch-bot-bad", "user-1"): REQUIRED_PERMISSIONS,
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if rate_limit_path is not None and path == rate_limit_path:
            return httpx.Response(429, headers={"Retry-After": "3"}, json={"retry_after": 3})

        if path == "/api/v10/oauth2/token":
            return httpx.Response(200, json={"access_token": "ephemeral-token"})

        if path == "/api/v10/users/@me":
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bot "):
                return httpx.Response(200, json={"id": "bot-1", "username": "orb-bot"})
            return httpx.Response(200, json={"id": "op-1", "username": "operator"})

        if path == "/api/v10/guilds/g-1/channels":
            return httpx.Response(
                200,
                json=[
                    {"id": "ch-1", "guild_id": "g-1", "name": "general", "type": 0, "nsfw": False},
                    {
                        "id": "ch-denied",
                        "guild_id": "g-1",
                        "name": "locked",
                        "type": 0,
                        "nsfw": False,
                    },
                    {
                        "id": "ch-bot-bad",
                        "guild_id": "g-1",
                        "name": "bot-blind",
                        "type": 0,
                        "nsfw": False,
                    },
                ],
            )

        if "/permissions/member/" in path:
            parts = path.split("/")
            channel_id = parts[4]
            user_id = parts[7]
            perm = resolved_perms.get((channel_id, user_id))
            if perm is None:
                return httpx.Response(404, json={"message": "Unknown Member"})
            return httpx.Response(200, json={"permissions": str(perm)})

        if path == "/api/v10/channels/ch-1/messages":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "m-rest-1",
                        "author": {"username": "alice", "global_name": "Alice"},
                        "timestamp": "2026-11-25T12:00:00+00:00",
                        "content": "Initial REST message",
                    }
                ],
            )

        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _create_user_session(repo: OrbRepository, user_id: str = "user-1") -> tuple[str, str]:
    session = repo.create_session(
        discord_user_id=user_id,
        device_name="Test Device",
        device_id="dev-1",
        platform="macos",
        refresh_token=f"refresh-{user_id}",
    )
    access_token, _ = create_access_token(session.session_id, user_id, TEST_SECRET)
    return session.session_id, access_token


class _AsgiSseSession:
    """In-process ASGI driver for testing live StreamingResponse SSE streams without buffering."""

    def __init__(self, app: Any, path: str, headers: dict[str, str] | None = None) -> None:
        self._app = app
        self._path = path
        self._headers = headers or {}
        self._receive_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._body_queue: asyncio.Queue[str | None] = asyncio.Queue()
        self._started = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self.status_code: int = 0
        self.headers: dict[str, str] = {}

    async def start(self) -> None:
        raw_headers = [
            (key.lower().encode("latin-1"), value.encode("latin-1"))
            for key, value in self._headers.items()
        ]
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": self._path,
            "raw_path": self._path.encode("ascii"),
            "query_string": b"",
            "headers": raw_headers,
            "server": ("orb.example.com", 443),
            "client": ("127.0.0.1", 55555),
        }

        async def receive() -> dict[str, Any]:
            return await self._receive_queue.get()

        async def send(message: dict[str, Any]) -> None:
            msg_type = message["type"]
            if msg_type == "http.response.start":
                self.status_code = int(message["status"])
                self.headers = {
                    k.decode("latin-1").lower(): v.decode("latin-1")
                    for k, v in message.get("headers", [])
                }
                self._started.set()
            elif msg_type == "http.response.body":
                body = message.get("body", b"")
                if body:
                    await self._body_queue.put(body.decode("utf-8"))
                if not message.get("more_body", False):
                    await self._body_queue.put(None)

        async def _runner() -> None:
            try:
                await self._app(scope, receive, send)
            finally:
                self._started.set()
                await self._body_queue.put(None)

        self._task = asyncio.create_task(_runner())
        await asyncio.wait_for(self._started.wait(), timeout=2.0)

    async def next_chunk(self, timeout: float = 2.0) -> str | None:
        return await asyncio.wait_for(self._body_queue.get(), timeout=timeout)

    async def disconnect(self) -> None:
        await self._receive_queue.put({"type": "http.disconnect"})
        if self._task is not None:
            await asyncio.wait_for(self._task, timeout=2.0)

    async def wait_closed(self, timeout: float = 2.0) -> None:
        if self._task is not None:
            await asyncio.wait_for(self._task, timeout=timeout)


def _parse_sse_chunk(chunk: str) -> tuple[str | None, dict[str, Any] | None]:
    event_name: str | None = None
    data_lines: list[str] = []
    for line in chunk.splitlines():
        if line.startswith(":"):
            return None, None
        if line.startswith("event:"):
            event_name = line.removeprefix("event:").strip()
        elif line.startswith("data:"):
            data_lines.append(line.removeprefix("data:").strip())
    if not data_lines:
        return event_name, None
    return event_name, json.loads("\n".join(data_lines))


def test_normalize_gateway_dispatch_and_broker_routing() -> None:
    create_events = normalize_gateway_dispatch(
        "MESSAGE_CREATE",
        {
            "id": "m-1",
            "guild_id": "g-1",
            "channel_id": "ch-1",
            "author": {"username": "alice", "global_name": "Alice"},
            "timestamp": "2026-11-25T12:01:00+00:00",
            "content": "Hello live!",
        },
    )
    assert len(create_events) == 1
    assert create_events[0].to_sse_payload() == {
        "type": "message_create",
        "guild_id": "g-1",
        "channel_id": "ch-1",
        "message": {
            "id": "m-1",
            "author_name": "Alice",
            "author_avatar_url": None,
            "timestamp": "2026-11-25T12:01:00+00:00",
            "content": "Hello live!",
        },
    }

    # Partial edit (only content + id) is preserved; embed-only edit (no content) is skipped.
    partial_update = normalize_gateway_dispatch(
        "MESSAGE_UPDATE",
        {"id": "m-1", "guild_id": "g-1", "channel_id": "ch-1", "content": "Edited text"},
    )
    assert len(partial_update) == 1
    assert partial_update[0].to_sse_payload() == {
        "type": "message_update",
        "guild_id": "g-1",
        "channel_id": "ch-1",
        "message": {"id": "m-1", "content": "Edited text"},
    }
    assert (
        normalize_gateway_dispatch(
            "MESSAGE_UPDATE",
            {"id": "m-1", "guild_id": "g-1", "channel_id": "ch-1", "embeds": [{"title": "x"}]},
        )
        == []
    )

    bulk_deletes = normalize_gateway_dispatch(
        "MESSAGE_DELETE_BULK",
        {"ids": ["m-1", "m-2"], "guild_id": "g-1", "channel_id": "ch-1"},
    )
    assert [ev.message_id for ev in bulk_deletes] == ["m-1", "m-2"]

    # Broker bounded queue drops oldest on overflow and isolates channels/guilds.
    broker = ChannelEventBroker(max_queue_size=2)
    sub_ch1 = broker.subscribe("g-1", "ch-1", session_id="s-1")
    sub_ch2 = broker.subscribe("g-1", "ch-2", session_id="s-2")
    sub_other_guild = broker.subscribe("g-other", "ch-1", session_id="s-3")
    assert broker.subscriber_count() == 3
    assert broker.subscriber_count("ch-1") == 2

    for idx in range(3):
        delivered = broker.publish(
            ChannelStreamEvent(
                event_type="message_create",
                guild_id="g-1",
                channel_id="ch-1",
                message_id=f"m-{idx}",
                author_name="Alice",
                timestamp="2026-11-25T12:00:00+00:00",
                content=f"msg {idx}",
            )
        )
        assert delivered == 1

    assert sub_ch1.queue.qsize() == 2
    assert sub_ch2.queue.empty()
    assert sub_other_guild.queue.empty()
    # Oldest (m-0) was dropped; m-1 and m-2 remain.
    first = sub_ch1.queue.get_nowait()
    second = sub_ch1.queue.get_nowait()
    assert first is not None and first.message_id == "m-1"
    assert second is not None and second.message_id == "m-2"

    sub_ch1.close()
    sub_ch2.close()
    sub_other_guild.close()
    assert broker.subscriber_count() == 0


async def test_gateway_hello_identify_heartbeat_dispatch_resume_and_invalid_session(
    tmp_path: Path,
) -> None:
    settings = _make_settings(tmp_path)
    broker = ChannelEventBroker()
    sub = broker.subscribe("g-1", "ch-1", session_id="sess-1")

    ws1 = FakeWebSocket()
    ws2 = FakeWebSocket()
    ws3 = FakeWebSocket()
    sockets = [ws1, ws2, ws3]
    connected_urls: list[str] = []

    @asynccontextmanager
    async def fake_connect(url: str) -> AsyncIterator[FakeWebSocket]:
        connected_urls.append(url)
        yield sockets.pop(0)

    gateway = DiscordGatewayClient(
        settings,
        broker,
        ws_connect=fake_connect,
        base_backoff_seconds=0.01,
        max_backoff_seconds=0.02,
        jitter_fn=lambda: 0.0,
    )

    await gateway.start()

    # Connection 1: HELLO -> IDENTIFY + Heartbeat -> READY -> MESSAGE_CREATE -> OP_RECONNECT
    ws1.push({"op": 10, "d": {"heartbeat_interval": 40}})
    await ws1.wait_for_sent_count(2)

    sent_ops = [frame["op"] for frame in ws1.sent]
    assert 2 in sent_ops  # IDENTIFY
    assert 1 in sent_ops  # HEARTBEAT
    identify = next(frame for frame in ws1.sent if frame["op"] == 2)
    assert identify["d"]["intents"] == MINIMAL_GATEWAY_INTENTS
    assert identify["d"]["token"] == settings.orb_discord_bot_token

    # Acknowledge heartbeat and also trigger server-requested op=1 heartbeat
    ws1.push({"op": 11, "d": None})
    ws1.push(
        {
            "op": 0,
            "s": 7,
            "t": "READY",
            "d": {
                "session_id": "gw-sess-1",
                "resume_gateway_url": "wss://resume.discord.test",
            },
        }
    )
    ws1.push({"op": 1, "d": None})
    ws1.push(
        {
            "op": 0,
            "s": 8,
            "t": "MESSAGE_CREATE",
            "d": {
                "id": "m-live-1",
                "guild_id": "g-1",
                "channel_id": "ch-1",
                "author": {"username": "bob", "global_name": "Bob"},
                "timestamp": "2026-11-25T12:10:00+00:00",
                "content": "Realtime message!",
            },
        }
    )

    delivered = await asyncio.wait_for(sub.get(), timeout=2.0)
    assert delivered is not None
    assert delivered.event_type == "message_create"
    assert delivered.message_id == "m-live-1"
    assert delivered.content == "Realtime message!"
    assert gateway.session_id == "gw-sess-1"
    assert gateway.sequence == 8

    # Server requests RECONNECT (op=7) -> gateway connects to resume_gateway_url and sends RESUME
    ws1.push({"op": 7, "d": None})
    ws2.push({"op": 10, "d": {"heartbeat_interval": 60_000}})
    await ws2.wait_for_sent_count(1)

    assert connected_urls[1] == "wss://resume.discord.test/?v=10&encoding=json"
    resume_frame = next(frame for frame in ws2.sent if frame["op"] == 6)
    assert resume_frame["d"]["session_id"] == "gw-sess-1"
    assert resume_frame["d"]["seq"] == 8

    # Server sends INVALID_SESSION (op=9, d=False) -> clears session and sends fresh IDENTIFY
    ws2.push({"op": 9, "d": False})
    ws3.push({"op": 10, "d": {"heartbeat_interval": 60_000}})
    await ws3.wait_for_sent_count(1)

    assert connected_urls[2] == "wss://gateway.discord.gg/?v=10&encoding=json"
    reidentify = next(frame for frame in ws3.sent if frame["op"] == 2)
    assert reidentify["d"]["intents"] == MINIMAL_GATEWAY_INTENTS

    await gateway.stop()
    assert gateway.is_running is False
    assert gateway.is_connected is False
    assert ws3.closed is True
    sub.close()


async def test_gateway_fatal_close_code_stops_cleanly_without_secret_leak(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = _make_settings(tmp_path, bot_token="ULTRA_SECRET_TOKEN_999")
    broker = ChannelEventBroker()
    connect_attempts = 0

    @asynccontextmanager
    async def failing_connect(_url: str) -> AsyncIterator[FakeWebSocket]:
        nonlocal connect_attempts
        connect_attempts += 1
        ws = FakeWebSocket(
            close_error=ConnectionClosedError(
                rcvd=Close(4004, "Authentication failed"),
                sent=None,
            )
        )
        ws.end()
        yield ws

    gateway = DiscordGatewayClient(
        settings,
        broker,
        ws_connect=failing_connect,
        base_backoff_seconds=0.01,
        max_backoff_seconds=0.01,
    )

    with caplog.at_level(logging.WARNING):
        await gateway.start()
        assert gateway._run_task is not None
        await asyncio.wait_for(gateway._run_task, timeout=2.0)

    assert connect_attempts == 1
    assert gateway.last_close_code == 4004
    assert gateway.is_running is False
    assert "ULTRA_SECRET_TOKEN_999" not in caplog.text


async def test_sse_fail_closed_auth_permissions_and_bot_unavailable(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    repo = OrbRepository(settings.orb_db_path)
    session_id, access_token = _create_user_session(repo)
    headers = {"Authorization": f"Bearer {access_token}"}

    discord_client = DiscordClient(settings, transport=_build_discord_mock())
    app = create_app(settings, repository=repo, discord_client=discord_client)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://orb.example.com") as client:
        # 401: missing Bearer token
        no_auth = await client.get("/api/v1/guilds/g-1/channels/ch-1/stream")
        assert no_auth.status_code == 401
        assert no_auth.headers["cache-control"] == "no-store"

        # 401: invalid token
        bad_auth = await client.get(
            "/api/v1/guilds/g-1/channels/ch-1/stream",
            headers={"Authorization": "Bearer not-a-valid-token"},
        )
        assert bad_auth.status_code == 401
        assert bad_auth.json()["code"] == "invalid_token"

        # 403: user lacks READ_MESSAGE_HISTORY
        denied = await client.get("/api/v1/guilds/g-1/channels/ch-denied/stream", headers=headers)
        assert denied.status_code == 403
        assert denied.json()["code"] == "access_denied"

        # 403: channel not in guild
        unknown_ch = await client.get("/api/v1/guilds/g-1/channels/ch-missing/stream", headers=headers)
        assert unknown_ch.status_code == 403
        assert unknown_ch.json()["code"] == "access_denied"

        # 503: bot lacks permissions on channel
        bot_bad = await client.get("/api/v1/guilds/g-1/channels/ch-bot-bad/stream", headers=headers)
        assert bot_bad.status_code == 503
        assert bot_bad.json()["code"] == "bot_unavailable"

        # 503: bot disabled in repository
        repo.set_bot_enabled(False)
        bot_off = await client.get("/api/v1/guilds/g-1/channels/ch-1/stream", headers=headers)
        assert bot_off.status_code == 503
        assert bot_off.json()["code"] == "bot_unavailable"
        repo.set_bot_enabled(True)

        # 401: revoked session
        repo.revoke_session(session_id)
        revoked = await client.get("/api/v1/guilds/g-1/channels/ch-1/stream", headers=headers)
        assert revoked.status_code == 401
        assert revoked.json()["code"] == "session_revoked"

    assert app.state.event_broker.subscriber_count() == 0
    await discord_client.aclose()
    repo.close()


async def test_sse_live_create_update_delete_keepalive_disconnect_and_no_persistence(
    tmp_path: Path,
) -> None:
    settings = _make_settings(tmp_path)
    repo = OrbRepository(settings.orb_db_path)
    _, access_token = _create_user_session(repo)
    headers = {"Authorization": f"Bearer {access_token}"}

    broker = ChannelEventBroker()
    ws = FakeWebSocket()

    @asynccontextmanager
    async def fake_connect(_url: str) -> AsyncIterator[FakeWebSocket]:
        yield ws

    gateway = DiscordGatewayClient(
        settings,
        broker,
        is_bot_enabled=repo.is_bot_enabled,
        ws_connect=fake_connect,
        base_backoff_seconds=0.01,
        max_backoff_seconds=0.01,
        jitter_fn=lambda: 0.0,
    )
    discord_client = DiscordClient(settings, transport=_build_discord_mock())
    app = create_app(
        settings,
        repository=repo,
        discord_client=discord_client,
        event_broker=broker,
        gateway_manager=gateway,
        sse_keepalive_interval=0.05,
    )

    secret_live_marker = "EPHEMERAL_LIVE_CHAT_MARKER_777"

    await gateway.start()
    ws.push({"op": 10, "d": {"heartbeat_interval": 60_000}})
    await ws.wait_for_sent_count(1)
    ws.push({"op": 0, "s": 1, "t": "READY", "d": {"session_id": "s-live"}})

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://orb.example.com") as client:
        # Backward-compatible REST messages endpoint still works identically
        rest_resp = await client.get("/api/v1/guilds/g-1/channels/ch-1/messages", headers=headers)
        assert rest_resp.status_code == 200
        assert rest_resp.json()["messages"][0]["id"] == "m-rest-1"

    sse = _AsgiSseSession(app, "/api/v1/guilds/g-1/channels/ch-1/stream", headers=headers)
    await sse.start()
    assert sse.status_code == 200
    assert sse.headers["content-type"].startswith("text/event-stream")
    assert sse.headers["cache-control"] == "no-store"
    assert sse.headers["x-accel-buffering"] == "no"

    # 1. Initial ready frame
    ready_chunk = await sse.next_chunk()
    assert ready_chunk is not None
    ev_name, ev_data = _parse_sse_chunk(ready_chunk)
    assert ev_name == "ready"
    assert ev_data == {"guild_id": "g-1", "channel_id": "ch-1"}
    assert broker.subscriber_count("ch-1") == 1

    # 2. Keepalive comment emitted when idle
    keepalive_chunk = await sse.next_chunk()
    assert keepalive_chunk == ": keepalive\n\n"

    # 3. Gateway dispatches create, update, delete -> delivered over SSE
    ws.push(
        {
            "op": 0,
            "s": 2,
            "t": "MESSAGE_CREATE",
            "d": {
                "id": "m-live-99",
                "guild_id": "g-1",
                "channel_id": "ch-1",
                "author": {"username": "alice", "global_name": "Alice"},
                "timestamp": "2026-11-25T12:15:00+00:00",
                "content": secret_live_marker,
            },
        }
    )
    ws.push(
        {
            "op": 0,
            "s": 3,
            "t": "MESSAGE_UPDATE",
            "d": {
                "id": "m-live-99",
                "guild_id": "g-1",
                "channel_id": "ch-1",
                "content": f"{secret_live_marker}-edited",
            },
        }
    )
    ws.push(
        {
            "op": 0,
            "s": 4,
            "t": "MESSAGE_DELETE",
            "d": {
                "id": "m-live-99",
                "guild_id": "g-1",
                "channel_id": "ch-1",
            },
        }
    )

    received_events: list[tuple[str, dict[str, Any]]] = []
    while len(received_events) < 3:
        chunk = await sse.next_chunk()
        assert chunk is not None
        if chunk.startswith(":"):
            continue
        parsed_name, parsed_data = _parse_sse_chunk(chunk)
        assert parsed_name is not None and parsed_data is not None
        received_events.append((parsed_name, parsed_data))

    assert received_events[0][0] == "message_create"
    assert received_events[0][1]["message"]["id"] == "m-live-99"
    assert received_events[0][1]["message"]["content"] == secret_live_marker

    assert received_events[1][0] == "message_update"
    assert received_events[1][1]["message"] == {
        "id": "m-live-99",
        "content": f"{secret_live_marker}-edited",
    }

    assert received_events[2][0] == "message_delete"
    assert received_events[2][1]["message_id"] == "m-live-99"

    # After client disconnects, subscriber cleanup runs immediately in `finally:`.
    await sse.disconnect()
    assert broker.subscriber_count() == 0

    await gateway.stop()
    await discord_client.aclose()
    repo.close()

    # Non-persistence verification: neither SQLite tables nor raw DB file contain chat payloads.
    db_file = Path(settings.orb_db_path)
    raw_bytes = db_file.read_bytes()
    assert secret_live_marker.encode("utf-8") not in raw_bytes
    with sqlite3.connect(db_file) as conn:
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert tables == {"oauth_tickets", "flutter_sessions", "instance_state"}


def test_dashboard_bot_toggle_synchronizes_gateway_and_closes_streams(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    repo = OrbRepository(settings.orb_db_path)
    broker = ChannelEventBroker()
    sub = broker.subscribe("g-1", "ch-1", session_id="sess-active")

    class RecordingGateway:
        def __init__(self) -> None:
            self.running = False
            self.sync_calls: list[bool] = []

        async def start(self) -> None:
            self.running = True

        async def stop(self) -> None:
            self.running = False

        async def sync_bot_state(self, enabled: bool) -> None:
            self.sync_calls.append(enabled)
            self.running = enabled

    gateway = RecordingGateway()
    discord_client = DiscordClient(settings, transport=_build_discord_mock())
    app = create_app(
        settings,
        repository=repo,
        discord_client=discord_client,
        event_broker=broker,
        gateway_manager=gateway,
    )

    with TestClient(app, base_url="https://orb.example.com") as client:
        assert gateway.running is True

        # Sign in as operator
        login_resp = client.get("/dashboard/login", follow_redirects=False)
        state = parse_qs(urlparse(login_resp.headers["location"]).query)["state"][0]
        cb_resp = client.get(
            "/dashboard/callback",
            params={"code": "op-code", "state": state},
            follow_redirects=False,
        )
        assert cb_resp.status_code == 303
        dash = client.get("/dashboard")
        csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', dash.text)
        assert csrf_match is not None
        csrf_token = csrf_match.group(1)

        # Disable bot -> Gateway stops and active SSE subscribers receive close sentinel
        off_resp = client.post(
            "/dashboard/bot/toggle",
            data={"csrf_token": csrf_token, "enabled": "false"},
            follow_redirects=False,
        )
        assert off_resp.status_code == 303
        assert gateway.running is False
        assert gateway.sync_calls == [False]
        assert sub.queue.get_nowait() is None

        # Re-enable bot -> Gateway resumes
        on_resp = client.post(
            "/dashboard/bot/toggle",
            data={"csrf_token": csrf_token, "enabled": "true"},
            follow_redirects=False,
        )
        assert on_resp.status_code == 303
        assert gateway.running is True
        assert gateway.sync_calls == [False, True]

    # Shutdown stops gateway cleanly
    assert gateway.running is False
    sub.close()
    repo.close()


async def test_gateway_heartbeat_timeout_and_bot_enabled_sync(tmp_path: Path) -> None:
    # Unconfigured bot token: start() must remain inactive
    no_token_settings = _make_settings(tmp_path, bot_token="")
    broker = ChannelEventBroker()
    connect_calls = 0

    @asynccontextmanager
    async def counting_connect(_url: str) -> AsyncIterator[FakeWebSocket]:
        nonlocal connect_calls
        connect_calls += 1
        yield FakeWebSocket()

    inactive_gw = DiscordGatewayClient(no_token_settings, broker, ws_connect=counting_connect)
    await inactive_gw.start()
    assert inactive_gw.is_running is False
    assert connect_calls == 0

    # Configured bot token with zombie heartbeat (no ACK) -> closes with 4000 & reconnects
    settings = _make_settings(tmp_path)
    bot_enabled_flag = True
    ws_first = FakeWebSocket()
    ws_second = FakeWebSocket()
    ws_resumed = FakeWebSocket()
    pool = [ws_first, ws_second, ws_resumed]

    @asynccontextmanager
    async def pooled_connect(_url: str) -> AsyncIterator[FakeWebSocket]:
        yield pool.pop(0)

    gw = DiscordGatewayClient(
        settings,
        broker,
        is_bot_enabled=lambda: bot_enabled_flag,
        ws_connect=pooled_connect,
        base_backoff_seconds=0.01,
        max_backoff_seconds=0.01,
        jitter_fn=lambda: 0.0,
    )
    await gw.start()

    # Hello with short 20ms interval; do NOT send op=11 ACK -> second tick triggers zombie close
    ws_first.push({"op": 10, "d": {"heartbeat_interval": 20}})
    ws_first.push({"op": 0, "s": 3, "t": "READY", "d": {"session_id": "s-zombie"}})
    ws_second.push({"op": 10, "d": {"heartbeat_interval": 60_000}})
    await ws_second.wait_for_sent_count(1)
    assert 4000 in ws_first.close_codes
    assert any(frame["op"] == 6 and frame["d"]["session_id"] == "s-zombie" for frame in ws_second.sent)

    # Disabling bot stops Gateway & closes open SSE subscribers; re-enabling restarts it
    sub = broker.subscribe("g-1", "ch-1", session_id="s-1")
    bot_enabled_flag = False
    await gw.sync_bot_state(False)
    assert gw.is_running is False
    assert ws_second.closed is True
    assert sub.queue.get_nowait() is None
    sub.close()

    bot_enabled_flag = True
    await gw.sync_bot_state(True)
    ws_resumed.push({"op": 10, "d": {"heartbeat_interval": 60_000}})
    await ws_resumed.wait_for_sent_count(1)
    assert gw.is_running is True
    assert any(frame["op"] == 2 for frame in ws_resumed.sent)
    await gw.stop()


async def test_sse_stream_terminates_immediately_on_logout_revocation(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    repo = OrbRepository(settings.orb_db_path)
    _, access_token = _create_user_session(repo)
    headers = {"Authorization": f"Bearer {access_token}"}

    broker = ChannelEventBroker()
    discord_client = DiscordClient(settings, transport=_build_discord_mock())
    app = create_app(
        settings,
        repository=repo,
        discord_client=discord_client,
        event_broker=broker,
        sse_keepalive_interval=5.0,
    )

    sse = _AsgiSseSession(app, "/api/v1/guilds/g-1/channels/ch-1/stream", headers=headers)
    await sse.start()
    assert sse.status_code == 200
    ready_chunk = await sse.next_chunk()
    assert ready_chunk is not None
    assert _parse_sse_chunk(ready_chunk)[0] == "ready"
    assert broker.subscriber_count("ch-1") == 1

    # Revoke the active session via logout endpoint
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://orb.example.com") as client:
        logout_resp = await client.post("/api/v1/auth/logout", headers=headers)
        assert logout_resp.status_code == 200

    # Publish after revocation -> must not be delivered, stream closes cleanly
    broker.publish(
        ChannelStreamEvent(
            event_type="message_create",
            guild_id="g-1",
            channel_id="ch-1",
            message_id="m-after-revoke",
            author_name="Alice",
            timestamp="2026-11-25T12:20:00+00:00",
            content="MUST_NOT_BE_DELIVERED",
        )
    )
    remaining: list[str] = []
    while True:
        chunk = await sse.next_chunk()
        if chunk is None:
            break
        remaining.append(chunk)
    assert "MUST_NOT_BE_DELIVERED" not in "".join(remaining)

    await sse.wait_closed()
    assert broker.subscriber_count() == 0

    await discord_client.aclose()
    repo.close()


async def test_avatar_and_guild_icon_url_resolution_across_rest_and_sse(tmp_path: Path) -> None:
    # 1. Direct unit checks for author_avatar_url resolution priority
    pomelo_uid = "105000000000000000"
    expected_pomelo_idx = (int(pomelo_uid) >> 22) % 6

    # Priority 1: member.avatar beats author.avatar
    assert (
        resolve_author_avatar_url(
            {
                "guild_id": "900",
                "author": {"id": "100", "avatar": "user_av", "discriminator": "1234"},
                "member": {"avatar": "guild_av"},
            }
        )
        == "https://cdn.discordapp.com/guilds/900/users/100/avatars/guild_av.png?size=64"
    )
    # Priority 1 fallback guild_id kwarg when REST message payload omits guild_id
    assert (
        resolve_author_avatar_url(
            {
                "author": {"id": "100", "avatar": "user_av"},
                "member": {"avatar": "guild_av"},
            },
            guild_id="900",
        )
        == "https://cdn.discordapp.com/guilds/900/users/100/avatars/guild_av.png?size=64"
    )
    # Priority 2: author.avatar when member.avatar missing or blank
    assert (
        resolve_author_avatar_url(
            {
                "guild_id": "900",
                "author": {"id": "100", "avatar": "user_av", "discriminator": "1234"},
                "member": {"avatar": "   "},
            }
        )
        == "https://cdn.discordapp.com/avatars/100/user_av.png?size=64"
    )
    # Priority 3a: legacy discriminator (numeric and != "0") -> int(disc) % 5
    assert (
        resolve_author_avatar_url(
            {
                "guild_id": "900",
                "author": {"id": "100", "avatar": None, "discriminator": "1234"},
            }
        )
        == "https://cdn.discordapp.com/embed/avatars/4.png"
    )
    # Priority 3b: Pomelo discriminator == "0" -> (int(id) >> 22) % 6
    assert (
        resolve_author_avatar_url(
            {
                "guild_id": "900",
                "author": {"id": pomelo_uid, "avatar": "", "discriminator": "0"},
            }
        )
        == f"https://cdn.discordapp.com/embed/avatars/{expected_pomelo_idx}.png"
    )
    # Priority 3c: missing discriminator with numeric id -> (int(id) >> 22) % 6
    assert (
        resolve_author_avatar_url(
            {"author": {"id": pomelo_uid}},
        )
        == f"https://cdn.discordapp.com/embed/avatars/{expected_pomelo_idx}.png"
    )
    # Priority 4: non-numeric or missing author.id -> None
    assert resolve_author_avatar_url({"author": {"id": "not-numeric"}}) is None
    assert resolve_author_avatar_url({"author": {"username": "anon"}}) is None

    # Guild icon URL resolution
    assert (
        resolve_guild_icon_url("900", "icon_hash_abc")
        == "https://cdn.discordapp.com/icons/900/icon_hash_abc.png?size=64"
    )
    assert resolve_guild_icon_url("900", None) is None
    assert resolve_guild_icon_url("900", "  ") is None

    # 2. End-to-end REST /channels, REST /messages, SSE message_create & message_update,
    #    and non-persistence verification
    settings = _make_settings(tmp_path)
    repo = OrbRepository(settings.orb_db_path)
    _, access_token = _create_user_session(repo)
    headers = {"Authorization": f"Bearer {access_token}"}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v10/users/@me":
            return httpx.Response(200, json={"id": "bot-1", "username": "orb-bot"})
        if path == "/api/v10/users/@me/guilds":
            return httpx.Response(
                200,
                json=[
                    {"id": "900", "name": "Icon Guild", "icon": "guild_icon_hash_900"},
                    {"id": "901", "name": "Plain Guild", "icon": None},
                ],
            )
        if path == "/api/v10/guilds/900/channels":
            return httpx.Response(
                200,
                json=[
                    {"id": "ch-900", "guild_id": "900", "name": "general", "type": 0, "nsfw": False}
                ],
            )
        if path == "/api/v10/guilds/901/channels":
            return httpx.Response(
                200,
                json=[
                    {"id": "ch-901", "guild_id": "901", "name": "chat", "type": 0, "nsfw": False}
                ],
            )
        if "/permissions/member/" in path:
            return httpx.Response(200, json={"permissions": str(REQUIRED_PERMISSIONS)})
        if path == "/api/v10/channels/ch-900/messages":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "m-member",
                        "author": {
                            "id": "101",
                            "username": "alice",
                            "global_name": "Alice",
                            "avatar": "user_av_101",
                        },
                        "member": {"avatar": "member_av_101"},
                        "timestamp": "2026-11-25T12:00:00+00:00",
                        "content": "member avatar msg",
                    },
                    {
                        "id": "m-user",
                        "author": {
                            "id": "102",
                            "username": "bob",
                            "avatar": "user_av_102",
                        },
                        "timestamp": "2026-11-25T12:01:00+00:00",
                        "content": "user avatar msg",
                    },
                    {
                        "id": "m-legacy",
                        "author": {
                            "id": "103",
                            "username": "carol",
                            "avatar": None,
                            "discriminator": "0007",
                        },
                        "timestamp": "2026-11-25T12:02:00+00:00",
                        "content": "legacy default avatar",
                    },
                    {
                        "id": "m-pomelo",
                        "author": {
                            "id": pomelo_uid,
                            "username": "dave",
                            "avatar": None,
                            "discriminator": "0",
                        },
                        "timestamp": "2026-11-25T12:03:00+00:00",
                        "content": "pomelo default avatar",
                    },
                    {
                        "id": "m-none",
                        "author": {"username": "unknown"},
                        "timestamp": "2026-11-25T12:04:00+00:00",
                        "content": "no id avatar",
                    },
                ],
            )
        return httpx.Response(404)

    broker = ChannelEventBroker()
    ws = FakeWebSocket()

    @asynccontextmanager
    async def fake_connect(_url: str) -> AsyncIterator[FakeWebSocket]:
        yield ws

    gateway = DiscordGatewayClient(
        settings,
        broker,
        is_bot_enabled=repo.is_bot_enabled,
        ws_connect=fake_connect,
        base_backoff_seconds=0.01,
        max_backoff_seconds=0.01,
        jitter_fn=lambda: 0.0,
    )
    discord_client = DiscordClient(settings, transport=httpx.MockTransport(handler))
    app = create_app(
        settings,
        repository=repo,
        discord_client=discord_client,
        event_broker=broker,
        gateway_manager=gateway,
        sse_keepalive_interval=5.0,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://orb.example.com") as client:
        # REST /api/v1/channels includes guild_icon_url on guilds & channels
        ch_resp = await client.get("/api/v1/channels", headers=headers)
        assert ch_resp.status_code == 200
        assert ch_resp.json() == {
            "guilds": [
                {
                    "guild_id": "900",
                    "guild_name": "Icon Guild",
                    "guild_icon_url": "https://cdn.discordapp.com/icons/900/guild_icon_hash_900.png?size=64",
                    "channels": [
                        {
                            "guild_id": "900",
                            "guild_name": "Icon Guild",
                            "guild_icon_url": "https://cdn.discordapp.com/icons/900/guild_icon_hash_900.png?size=64",
                            "channel_id": "ch-900",
                            "channel_name": "general",
                        }
                    ],
                },
                {
                    "guild_id": "901",
                    "guild_name": "Plain Guild",
                    "guild_icon_url": None,
                    "channels": [
                        {
                            "guild_id": "901",
                            "guild_name": "Plain Guild",
                            "guild_icon_url": None,
                            "channel_id": "ch-901",
                            "channel_name": "chat",
                        }
                    ],
                },
            ]
        }

        # REST /messages returns resolved author_avatar_url for each priority
        msg_resp = await client.get(
            "/api/v1/guilds/900/channels/ch-900/messages",
            headers=headers,
        )
        assert msg_resp.status_code == 200
        by_id = {m["id"]: m for m in msg_resp.json()["messages"]}
        assert (
            by_id["m-member"]["author_avatar_url"]
            == "https://cdn.discordapp.com/guilds/900/users/101/avatars/member_av_101.png?size=64"
        )
        assert (
            by_id["m-user"]["author_avatar_url"]
            == "https://cdn.discordapp.com/avatars/102/user_av_102.png?size=64"
        )
        assert (
            by_id["m-legacy"]["author_avatar_url"]
            == "https://cdn.discordapp.com/embed/avatars/2.png"
        )
        assert (
            by_id["m-pomelo"]["author_avatar_url"]
            == f"https://cdn.discordapp.com/embed/avatars/{expected_pomelo_idx}.png"
        )
        assert by_id["m-none"]["author_avatar_url"] is None

    # SSE stream emits author_avatar_url on message_create and author-bearing message_update
    await gateway.start()
    ws.push({"op": 10, "d": {"heartbeat_interval": 60_000}})
    await ws.wait_for_sent_count(1)
    ws.push({"op": 0, "s": 1, "t": "READY", "d": {"session_id": "s-av"}})

    sse = _AsgiSseSession(app, "/api/v1/guilds/900/channels/ch-900/stream", headers=headers)
    await sse.start()
    assert sse.status_code == 200
    assert await sse.next_chunk() is not None  # ready

    ws.push(
        {
            "op": 0,
            "s": 2,
            "t": "MESSAGE_CREATE",
            "d": {
                "id": "m-sse-1",
                "guild_id": "900",
                "channel_id": "ch-900",
                "author": {"id": "201", "username": "eve", "avatar": "sse_user_av"},
                "member": {"avatar": "sse_member_av"},
                "timestamp": "2026-11-25T12:30:00+00:00",
                "content": "live with avatar",
            },
        }
    )
    ws.push(
        {
            "op": 0,
            "s": 3,
            "t": "MESSAGE_UPDATE",
            "d": {
                "id": "m-sse-1",
                "guild_id": "900",
                "channel_id": "ch-900",
                "author": {"id": "201", "username": "eve", "avatar": "sse_user_av_updated"},
                "content": "edited with author avatar",
            },
        }
    )
    ws.push(
        {
            "op": 0,
            "s": 4,
            "t": "MESSAGE_UPDATE",
            "d": {
                "id": "m-sse-1",
                "guild_id": "900",
                "channel_id": "ch-900",
                "content": "partial content-only edit",
            },
        }
    )

    ev1_name, ev1_data = _parse_sse_chunk(await sse.next_chunk() or "")
    ev2_name, ev2_data = _parse_sse_chunk(await sse.next_chunk() or "")
    ev3_name, ev3_data = _parse_sse_chunk(await sse.next_chunk() or "")

    assert ev1_name == "message_create"
    assert ev1_data is not None
    assert (
        ev1_data["message"]["author_avatar_url"]
        == "https://cdn.discordapp.com/guilds/900/users/201/avatars/sse_member_av.png?size=64"
    )

    assert ev2_name == "message_update"
    assert ev2_data is not None
    assert (
        ev2_data["message"]["author_avatar_url"]
        == "https://cdn.discordapp.com/avatars/201/sse_user_av_updated.png?size=64"
    )

    assert ev3_name == "message_update"
    assert ev3_data is not None
    assert "author_avatar_url" not in ev3_data["message"]
    assert ev3_data["message"]["content"] == "partial content-only edit"

    await sse.disconnect()
    await gateway.stop()
    await discord_client.aclose()
    repo.close()

    # Non-persistence check: no avatar/icon URLs or message payloads in SQLite on disk
    raw_db = Path(settings.orb_db_path).read_bytes()
    for ephemeral in (
        b"guild_icon_hash_900",
        b"member_av_101",
        b"sse_member_av",
        b"sse_user_av_updated",
        b"live with avatar",
    ):
        assert ephemeral not in raw_db
