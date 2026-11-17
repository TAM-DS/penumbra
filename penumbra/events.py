"""Layer 1 — normalized telemetry events and the event bus.

Every signal Penumbra sees (IAM logs, CloudTrail, Git audit, Slack metadata,
email, model-gateway logs, OSINT hits) is normalized into one ``Event`` shape
before any agent can touch it.

The trust boundary is drawn *inside* the event:

* Structured metadata (who, what, when, where) is emitted by systems we
  operate, so it is treated as an internal signal.
* Free text (``content``: an email body, a web page, a chat message, a paste
  site dump) was written by someone else, possibly an adversary. It is
  **never** shown to an agent until Layer 4's quarantine has processed it.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Source(str, Enum):
    OKTA = "okta"
    CLOUDTRAIL = "cloudtrail"
    GITHUB = "github"
    SLACK = "slack"
    EMAIL = "email"
    DLP = "dlp"
    MODEL_GATEWAY = "model_gateway"
    OSINT = "osint"
    HR = "hr"


@dataclass(frozen=True)
class Event:
    id: str
    ts: datetime
    source: Source
    kind: str
    actor: str
    target: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)
    # Untrusted, externally-authored text. Must pass quarantine before use.
    content: str | None = None

    @property
    def has_untrusted_content(self) -> bool:
        return bool(self.content)

    def metadata_view(self) -> dict[str, Any]:
        """What an agent may see *without* quarantine: metadata only."""
        return {
            "id": self.id,
            "ts": self.ts.isoformat(),
            "source": self.source.value,
            "kind": self.kind,
            "actor": self.actor,
            "target": self.target,
            "attrs": self.attrs,
            "has_content": self.has_untrusted_content,
        }

    def to_json(self) -> str:
        d = asdict(self)
        d["ts"] = self.ts.isoformat()
        d["source"] = self.source.value
        return json.dumps(d, sort_keys=True)


class EventBus:
    """In-process async event bus.

    The interface is deliberately the shape of Kafka / Redis Streams
    (publish to a topic, consume as a stream) so a production deployment can
    swap in ``RedisStreamBus`` without changing any agent code.
    """

    def __init__(self) -> None:
        self._queue: asyncio.Queue[Event | None] = asyncio.Queue()
        self.published = 0

    async def publish(self, event: Event) -> None:
        self.published += 1
        await self._queue.put(event)

    async def publish_many(self, events: Iterable[Event]) -> None:
        for e in events:
            await self.publish(e)

    async def close(self) -> None:
        await self._queue.put(None)

    async def consume(self) -> AsyncIterator[Event]:
        while True:
            item = await self._queue.get()
            if item is None:
                return
            yield item


class RedisStreamBus(EventBus):  # pragma: no cover - requires a Redis server
    """Redis Streams adapter. ``pip install redis`` and set PENUMBRA_REDIS_URL."""

    def __init__(self, url: str, stream: str = "penumbra:telemetry") -> None:
        super().__init__()
        import redis.asyncio as redis  # type: ignore

        self._r = redis.from_url(url)
        self._stream = stream

    async def publish(self, event: Event) -> None:
        self.published += 1
        await self._r.xadd(self._stream, {"event": event.to_json()})

    async def close(self) -> None:
        # End-of-stream is detected by an empty blocking read in consume();
        # the connection stays open until consumption finishes.
        return None

    async def consume(self) -> AsyncIterator[Event]:
        last = "0-0"
        while True:
            resp = await self._r.xread({self._stream: last}, block=5000, count=200)
            if not resp:
                await self._r.aclose()
                return
            for _stream, entries in resp:
                for entry_id, fields in entries:
                    last = entry_id
                    yield event_from_json(fields[b"event"])


def event_from_json(raw: str | bytes) -> Event:
    d = json.loads(raw)
    return Event(
        id=d["id"],
        ts=datetime.fromisoformat(d["ts"]),
        source=Source(d["source"]),
        kind=d["kind"],
        actor=d["actor"],
        target=d.get("target"),
        attrs=d.get("attrs") or {},
        content=d.get("content"),
    )
