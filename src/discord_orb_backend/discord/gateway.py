"""Discord Gateway v10 WebSocket client with resume, heartbeat, and in-memory dispatch."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import random
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import websockets
from websockets.asyncio.client import connect as websockets_connect
from websockets.exceptions import ConnectionClosed

from ..config import Settings
from .broker import ChannelEventBroker, ChannelStreamEvent
from .models import resolve_author_avatar_url

logger = logging.getLogger(__name__)

DEFAULT_GATEWAY_URL = "wss://gateway.discord.gg/?v=10&encoding=json"

# Minimal intents required for guild text message previews.
INTENT_GUILDS: int = 1 << 0
INTENT_GUILD_MESSAGES: int = 1 << 9
INTENT_MESSAGE_CONTENT: int = 1 << 15
MINIMAL_GATEWAY_INTENTS: int = INTENT_GUILDS | INTENT_GUILD_MESSAGES | INTENT_MESSAGE_CONTENT

OP_DISPATCH = 0
OP_HEARTBEAT = 1
OP_IDENTIFY = 2
OP_RESUME = 6
OP_RECONNECT = 7
OP_INVALID_SESSION = 9
OP_HELLO = 10
OP_HEARTBEAT_ACK = 11

# Close codes where reconnecting will not succeed without operator intervention.
FATAL_CLOSE_CODES: frozenset[int] = frozenset({4004, 4010, 4011, 4012, 4013, 4014})
# Close codes where the previous session cannot be resumed and must re-identify.
NON_RESUMABLE_CLOSE_CODES: frozenset[int] = frozenset({4007, 4009})


def _extract_author_name(author: Any) -> str | None:
    if not isinstance(author, dict):
        return None
    name = author.get("global_name") or author.get("username")
    if name is None:
        return None
    return str(name)


def _normalize_resume_url(resume_url: str) -> str:
    parsed = urlsplit(resume_url)
    query_pairs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query_pairs.setdefault("v", "10")
    query_pairs.setdefault("encoding", "json")
    path = parsed.path or "/"
    return urlunsplit(
        (parsed.scheme, parsed.netloc, path, urlencode(query_pairs), "")
    )


def _extract_close_code(exc: BaseException) -> int | None:
    rcvd = getattr(exc, "rcvd", None)
    if rcvd is not None:
        code = getattr(rcvd, "code", None)
        if isinstance(code, int):
            return code
    code = getattr(exc, "code", None)
    return code if isinstance(code, int) else None


def normalize_gateway_dispatch(event_name: str, data: Any) -> list[ChannelStreamEvent]:
    """Convert a Discord Gateway Dispatch payload into normalized in-memory events."""
    if not isinstance(data, dict):
        return []

    raw_channel_id = data.get("channel_id")
    if not raw_channel_id:
        return []
    channel_id = str(raw_channel_id)
    raw_guild_id = data.get("guild_id")
    guild_id = str(raw_guild_id) if raw_guild_id else None

    if event_name == "MESSAGE_CREATE":
        message_id = data.get("id")
        timestamp = data.get("timestamp")
        if not message_id or not timestamp:
            return []
        author_name = _extract_author_name(data.get("author")) or "Unknown"
        author_avatar_url = resolve_author_avatar_url(data, guild_id=guild_id)
        content = data.get("content")
        return [
            ChannelStreamEvent(
                event_type="message_create",
                guild_id=guild_id,
                channel_id=channel_id,
                message_id=str(message_id),
                author_name=author_name,
                author_avatar_url=author_avatar_url,
                include_author_avatar_url=True,
                timestamp=str(timestamp),
                content=str(content) if content is not None else "",
            )
        ]

    if event_name == "MESSAGE_UPDATE":
        message_id = data.get("id")
        if not message_id:
            return []
        # Skip embed-only or metadata-only updates that carry no text content change.
        if "content" not in data or data.get("content") is None:
            return []
        author_name = _extract_author_name(data.get("author"))
        has_author_info = isinstance(data.get("author"), dict) or isinstance(
            data.get("member"), dict
        )
        author_avatar_url = (
            resolve_author_avatar_url(data, guild_id=guild_id) if has_author_info else None
        )
        raw_timestamp = data.get("timestamp")
        timestamp = str(raw_timestamp) if raw_timestamp else None
        return [
            ChannelStreamEvent(
                event_type="message_update",
                guild_id=guild_id,
                channel_id=channel_id,
                message_id=str(message_id),
                author_name=author_name,
                author_avatar_url=author_avatar_url,
                include_author_avatar_url=has_author_info,
                timestamp=timestamp,
                content=str(data["content"]),
            )
        ]

    if event_name == "MESSAGE_DELETE":
        message_id = data.get("id")
        if not message_id:
            return []
        return [
            ChannelStreamEvent(
                event_type="message_delete",
                guild_id=guild_id,
                channel_id=channel_id,
                message_id=str(message_id),
            )
        ]

    if event_name == "MESSAGE_DELETE_BULK":
        ids = data.get("ids")
        if not isinstance(ids, list):
            return []
        return [
            ChannelStreamEvent(
                event_type="message_delete",
                guild_id=guild_id,
                channel_id=channel_id,
                message_id=str(message_id),
            )
            for message_id in ids
            if message_id
        ]

    return []


def _default_ws_connect(url: str) -> Any:
    return websockets_connect(
        url,
        ping_interval=None,
        open_timeout=10,
        close_timeout=5,
        max_size=4 * 1024 * 1024,
    )


class DiscordGatewayClient:
    """Lifecycle-managed Discord Gateway v10 client feeding an in-memory event broker."""

    def __init__(
        self,
        settings: Settings,
        broker: ChannelEventBroker,
        *,
        is_bot_enabled: Callable[[], bool] | None = None,
        gateway_url: str = DEFAULT_GATEWAY_URL,
        ws_connect: Callable[[str], Any] | None = None,
        base_backoff_seconds: float = 1.0,
        max_backoff_seconds: float = 60.0,
        jitter_fn: Callable[[], float] | None = None,
    ) -> None:
        self._settings = settings
        self._broker = broker
        self._is_bot_enabled = is_bot_enabled
        self._gateway_url = gateway_url
        self._ws_connect = ws_connect or _default_ws_connect
        self._base_backoff_seconds = max(0.0, base_backoff_seconds)
        self._max_backoff_seconds = max(self._base_backoff_seconds, max_backoff_seconds)
        self._jitter_fn = jitter_fn or random.random

        self._session_id: str | None = None
        self._resume_gateway_url: str | None = None
        self._sequence: int | None = None
        self._heartbeat_ack_received = True
        self._reconnect_attempt = 0
        self._last_close_code: int | None = None
        self._connected = False

        self._stop_event = asyncio.Event()
        self._stop_event.set()
        self._run_task: asyncio.Task[None] | None = None
        self._active_ws: Any | None = None

    @property
    def is_running(self) -> bool:
        """Whether the Gateway background loop is currently active."""
        return self._run_task is not None and not self._run_task.done()

    @property
    def is_connected(self) -> bool:
        """Whether a Gateway WebSocket session is currently open."""
        return self._connected

    @property
    def session_id(self) -> str | None:
        return self._session_id

    @property
    def sequence(self) -> int | None:
        return self._sequence

    @property
    def resume_gateway_url(self) -> str | None:
        return self._resume_gateway_url

    @property
    def last_close_code(self) -> int | None:
        return self._last_close_code

    def _can_run(self) -> bool:
        if not self._settings.bot_configured:
            return False
        return self._is_bot_enabled is None or bool(self._is_bot_enabled())

    def _clear_resume_state(self) -> None:
        self._session_id = None
        self._resume_gateway_url = None
        self._sequence = None

    def _resolve_connect_url(self) -> str:
        if self._session_id and self._sequence is not None and self._resume_gateway_url:
            return _normalize_resume_url(self._resume_gateway_url)
        return self._gateway_url

    def _next_backoff_delay(self) -> float:
        raw = self._base_backoff_seconds * (2 ** min(self._reconnect_attempt, 16))
        bounded = min(raw, self._max_backoff_seconds)
        self._reconnect_attempt += 1
        jitter = max(0.0, min(1.0, float(self._jitter_fn())))
        return bounded * (0.5 + 0.5 * jitter)

    async def start(self) -> None:
        """Start the background Gateway loop if bot token is configured and enabled."""
        if not self._can_run():
            return
        if self.is_running:
            return
        self._stop_event = asyncio.Event()
        self._reconnect_attempt = 0
        self._last_close_code = None
        self._run_task = asyncio.create_task(self._run_loop(), name="discord-gateway-v10")

    async def stop(self) -> None:
        """Stop the Gateway loop, close any open WebSocket, and clear runtime state."""
        self._stop_event.set()
        ws = self._active_ws
        self._active_ws = None
        if ws is not None:
            with contextlib.suppress(Exception):
                await ws.close(code=1000, reason="shutdown")

        task = self._run_task
        self._run_task = None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        self._connected = False
        self._clear_resume_state()

    async def aclose(self) -> None:
        """Async close hook compatible with FastAPI lifespan cleanup."""
        await self.stop()

    async def sync_bot_state(self, enabled: bool) -> None:
        """Synchronize Gateway lifecycle with runtime `bot_enabled` state."""
        if enabled and self._settings.bot_configured:
            await self.start()
        else:
            await self.stop()
            self._broker.close_all()

    async def _wait_or_stop(self, seconds: float) -> bool:
        """Sleep for `seconds` or return True immediately when stopped."""
        if seconds <= 0:
            return self._stop_event.is_set()
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)
            return True
        except TimeoutError:
            return self._stop_event.is_set()

    async def _send_json(self, ws: Any, payload: dict[str, Any]) -> None:
        await ws.send(json.dumps(payload, separators=(",", ":")))

    async def _send_identify(self, ws: Any) -> None:
        token = self._settings.orb_discord_bot_token
        await self._send_json(
            ws,
            {
                "op": OP_IDENTIFY,
                "d": {
                    "token": token,
                    "intents": MINIMAL_GATEWAY_INTENTS,
                    "properties": {
                        "os": "linux",
                        "browser": "discord-orb",
                        "device": "discord-orb",
                    },
                },
            },
        )

    async def _send_resume(self, ws: Any) -> None:
        token = self._settings.orb_discord_bot_token
        await self._send_json(
            ws,
            {
                "op": OP_RESUME,
                "d": {
                    "token": token,
                    "session_id": self._session_id,
                    "seq": self._sequence,
                },
            },
        )

    async def _send_heartbeat(self, ws: Any) -> None:
        await self._send_json(ws, {"op": OP_HEARTBEAT, "d": self._sequence})

    async def _heartbeat_loop(self, ws: Any, interval_seconds: float) -> None:
        jitter = max(0.0, min(1.0, float(self._jitter_fn())))
        if await self._wait_or_stop(interval_seconds * jitter):
            return

        while not self._stop_event.is_set():
            if not self._heartbeat_ack_received:
                logger.warning("Discord Gateway heartbeat ACK timed out; reconnecting.")
                with contextlib.suppress(Exception):
                    await ws.close(code=4000, reason="heartbeat timeout")
                return

            self._heartbeat_ack_received = False
            await self._send_heartbeat(ws)
            if await self._wait_or_stop(interval_seconds):
                return

    async def _handle_connection(self, ws: Any) -> bool:
        """Process Gateway frames for a single connection.

        Returns True when the caller should reconnect immediately (e.g., OP_RECONNECT),
        or False when normal backoff should apply.
        """
        heartbeat_task: asyncio.Task[None] | None = None
        self._heartbeat_ack_received = True
        self._connected = True
        self._active_ws = ws
        immediate_reconnect = False

        try:
            async for raw_frame in ws:
                if self._stop_event.is_set() or not self._can_run():
                    with contextlib.suppress(Exception):
                        await ws.close(code=1000, reason="disabled")
                    break

                if isinstance(raw_frame, bytes):
                    raw_text = raw_frame.decode("utf-8", errors="replace")
                else:
                    raw_text = str(raw_frame)

                try:
                    frame = json.loads(raw_text)
                except ValueError:
                    continue
                if not isinstance(frame, dict):
                    continue

                seq = frame.get("s")
                if isinstance(seq, int):
                    self._sequence = seq

                op = frame.get("op")
                data = frame.get("d")
                event_name = frame.get("t")

                if op == OP_HELLO:
                    if not isinstance(data, dict):
                        continue
                    interval_ms = data.get("heartbeat_interval")
                    if isinstance(interval_ms, (int, float)) and interval_ms > 0:
                        if heartbeat_task is not None:
                            heartbeat_task.cancel()
                            with contextlib.suppress(asyncio.CancelledError):
                                await heartbeat_task
                        heartbeat_task = asyncio.create_task(
                            self._heartbeat_loop(ws, float(interval_ms) / 1000.0),
                            name="discord-gateway-heartbeat",
                        )

                    if self._session_id and self._sequence is not None:
                        await self._send_resume(ws)
                    else:
                        await self._send_identify(ws)
                    continue

                if op == OP_HEARTBEAT:
                    await self._send_heartbeat(ws)
                    continue

                if op == OP_HEARTBEAT_ACK:
                    self._heartbeat_ack_received = True
                    continue

                if op == OP_RECONNECT:
                    immediate_reconnect = True
                    with contextlib.suppress(Exception):
                        await ws.close(code=4000, reason="gateway reconnect")
                    break

                if op == OP_INVALID_SESSION:
                    resumable = bool(data)
                    if not resumable:
                        self._clear_resume_state()
                    with contextlib.suppress(Exception):
                        await ws.close(code=4000, reason="invalid session")
                    break

                if op == OP_DISPATCH and isinstance(event_name, str):
                    if event_name == "READY" and isinstance(data, dict):
                        raw_sid = data.get("session_id")
                        if raw_sid:
                            self._session_id = str(raw_sid)
                        raw_resume = data.get("resume_gateway_url")
                        if raw_resume:
                            self._resume_gateway_url = str(raw_resume)
                        self._reconnect_attempt = 0
                        continue

                    if event_name == "RESUMED":
                        self._reconnect_attempt = 0
                        continue

                    for event in normalize_gateway_dispatch(event_name, data):
                        self._broker.publish(event)
        finally:
            self._connected = False
            if self._active_ws is ws:
                self._active_ws = None
            if heartbeat_task is not None:
                heartbeat_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await heartbeat_task

        return immediate_reconnect

    async def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            if not self._can_run():
                break

            connect_url = self._resolve_connect_url()
            immediate_reconnect = False
            try:
                async with self._ws_connect(connect_url) as ws:
                    immediate_reconnect = await self._handle_connection(ws)
            except asyncio.CancelledError:
                raise
            except ConnectionClosed as exc:
                close_code = _extract_close_code(exc)
                self._last_close_code = close_code
                if close_code in FATAL_CLOSE_CODES:
                    logger.error(
                        "Discord Gateway closed with fatal code %s; stopping Gateway client.",
                        close_code,
                    )
                    self._clear_resume_state()
                    break
                if close_code in NON_RESUMABLE_CLOSE_CODES:
                    self._clear_resume_state()
            except (OSError, websockets.exceptions.WebSocketException, RuntimeError):
                logger.warning("Discord Gateway connection error; scheduling reconnect.")

            if self._stop_event.is_set() or not self._can_run():
                break

            if not immediate_reconnect:
                delay = self._next_backoff_delay()
                if await self._wait_or_stop(delay):
                    break
