"""In-memory per-channel pub/sub broker for real-time Discord preview SSE streams.

No Discord message payloads are ever persisted to disk or SQLite; all events
live exclusively in bounded per-subscriber asyncio queues and are discarded
immediately on disconnect, revocation, or bot disable.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Literal, Self

StreamEventType = Literal["message_create", "message_update", "message_delete"]

DEFAULT_SUBSCRIBER_QUEUE_SIZE = 64


@dataclass(frozen=True, slots=True)
class ChannelStreamEvent:
    """Normalized in-memory message event published from Discord Gateway to SSE clients."""

    event_type: StreamEventType
    channel_id: str
    guild_id: str | None = None
    message_id: str | None = None
    author_name: str | None = None
    author_avatar_url: str | None = None
    include_author_avatar_url: bool = False
    timestamp: str | None = None
    content: str | None = None

    def to_sse_payload(self) -> dict[str, Any]:
        """Build the JSON-serializable payload emitted in the SSE `data:` field."""
        if self.event_type == "message_delete":
            return {
                "type": self.event_type,
                "guild_id": self.guild_id,
                "channel_id": self.channel_id,
                "message_id": self.message_id,
            }

        message_payload: dict[str, Any] = {"id": self.message_id}
        if self.author_name is not None:
            message_payload["author_name"] = self.author_name
        if (
            self.event_type == "message_create"
            or self.author_avatar_url is not None
            or self.include_author_avatar_url
        ):
            message_payload["author_avatar_url"] = self.author_avatar_url
        if self.timestamp is not None:
            message_payload["timestamp"] = self.timestamp
        if self.content is not None:
            message_payload["content"] = self.content

        return {
            "type": self.event_type,
            "guild_id": self.guild_id,
            "channel_id": self.channel_id,
            "message": message_payload,
        }

    def format_sse(self) -> str:
        """Render this event as a standard Server-Sent Events frame."""
        encoded = json.dumps(self.to_sse_payload(), separators=(",", ":"))
        return f"event: {self.event_type}\ndata: {encoded}\n\n"


def format_sse_frame(event_name: str, payload: dict[str, Any]) -> str:
    """Format an arbitrary named SSE event with a JSON payload."""
    encoded = json.dumps(payload, separators=(",", ":"))
    return f"event: {event_name}\ndata: {encoded}\n\n"


def _enqueue_bounded(
    queue: asyncio.Queue[ChannelStreamEvent | None],
    item: ChannelStreamEvent | None,
) -> None:
    """Insert an item into a bounded queue, dropping the oldest entry if full."""
    if queue.full():
        try:
            queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
    try:
        queue.put_nowait(item)
    except asyncio.QueueFull:
        pass


class ChannelSubscription:
    """Active subscriber handle backed by a bounded in-memory asyncio queue."""

    def __init__(
        self,
        *,
        broker: ChannelEventBroker,
        guild_id: str,
        channel_id: str,
        session_id: str | None,
        max_queue_size: int,
    ) -> None:
        self._broker = broker
        self.guild_id = guild_id
        self.channel_id = channel_id
        self.session_id = session_id
        self.queue: asyncio.Queue[ChannelStreamEvent | None] = asyncio.Queue(
            maxsize=max_queue_size
        )
        self._closed = False

    @property
    def closed(self) -> bool:
        """Whether this subscription has been closed and unregistered."""
        return self._closed

    async def get(self) -> ChannelStreamEvent | None:
        """Wait for the next channel event, or None if the stream was terminated."""
        return await self.queue.get()

    def _deliver(self, event: ChannelStreamEvent) -> None:
        if self._closed:
            return
        _enqueue_bounded(self.queue, event)

    def _signal_close(self) -> None:
        if self._closed:
            return
        _enqueue_bounded(self.queue, None)

    def close(self) -> None:
        """Unregister from the broker and purge any buffered events from memory."""
        if self._closed:
            return
        self._closed = True
        self._broker.unsubscribe(self)
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class ChannelEventBroker:
    """In-memory per-channel pub/sub broker for real-time Discord message events."""

    def __init__(self, *, max_queue_size: int = DEFAULT_SUBSCRIBER_QUEUE_SIZE) -> None:
        if max_queue_size < 1:
            raise ValueError("max_queue_size must be at least 1")
        self._max_queue_size = max_queue_size
        self._subscribers_by_channel: dict[str, set[ChannelSubscription]] = {}

    @property
    def max_queue_size(self) -> int:
        """Maximum buffered events retained per subscriber queue."""
        return self._max_queue_size

    def subscribe(
        self,
        guild_id: str,
        channel_id: str,
        *,
        session_id: str | None = None,
    ) -> ChannelSubscription:
        """Register a new bounded subscriber for a guild/channel stream."""
        subscription = ChannelSubscription(
            broker=self,
            guild_id=guild_id,
            channel_id=channel_id,
            session_id=session_id,
            max_queue_size=self._max_queue_size,
        )
        self._subscribers_by_channel.setdefault(channel_id, set()).add(subscription)
        return subscription

    def unsubscribe(self, subscription: ChannelSubscription) -> None:
        """Remove a subscriber and prune empty channel buckets."""
        channel_subs = self._subscribers_by_channel.get(subscription.channel_id)
        if channel_subs is None:
            return
        channel_subs.discard(subscription)
        if not channel_subs:
            self._subscribers_by_channel.pop(subscription.channel_id, None)

    def publish(self, event: ChannelStreamEvent) -> int:
        """Publish an event to matching subscribers in memory without blocking."""
        channel_subs = self._subscribers_by_channel.get(event.channel_id)
        if not channel_subs:
            return 0
        delivered = 0
        for sub in list(channel_subs):
            if event.guild_id is not None and sub.guild_id != event.guild_id:
                continue
            sub._deliver(event)
            delivered += 1
        return delivered

    def close_session(self, session_id: str) -> int:
        """Signal all active streams belonging to a revoked session to terminate."""
        signaled = 0
        for channel_subs in list(self._subscribers_by_channel.values()):
            for sub in list(channel_subs):
                if sub.session_id == session_id:
                    sub._signal_close()
                    signaled += 1
        return signaled

    def close_all(self) -> int:
        """Signal all active SSE subscribers to terminate immediately."""
        signaled = 0
        for channel_subs in list(self._subscribers_by_channel.values()):
            for sub in list(channel_subs):
                sub._signal_close()
                signaled += 1
        return signaled

    def subscriber_count(self, channel_id: str | None = None) -> int:
        """Return the number of active subscribers globally or for one channel."""
        if channel_id is not None:
            return len(self._subscribers_by_channel.get(channel_id, ()))
        return sum(len(subs) for subs in self._subscribers_by_channel.values())
