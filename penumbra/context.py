"""Shared runtime context for one investigation.

Holds the five layers' live objects and the ``emit`` channel that streams
everything (reasoning steps, graph updates, approval cards, guardrail
verdicts) to the UI and CLI.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .events import Event
from .guardrails import AuditLog, PolicyGate, Quarantine, ToolRegistry
from .memory import KnowledgeStore, Scratchpad, TemporalGraph

Emit = Callable[[str, dict[str, Any]], None]


@dataclass
class ControlPlane:
    """The simulated 'real world' that containment actions change."""

    revoked_keys: set[str] = field(default_factory=set)
    blocked_domains: set[str] = field(default_factory=set)
    suspended_users: set[str] = field(default_factory=set)
    mfa_reset_users: set[str] = field(default_factory=set)
    removed_bucket_policies: set[str] = field(default_factory=set)
    canaries: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class InvestigationContext:
    investigation_id: str
    events: list[Event]
    window_start: datetime
    graph: TemporalGraph
    scratchpad: Scratchpad
    knowledge: KnowledgeStore
    quarantine: Quarantine
    registry: ToolRegistry
    audit: AuditLog
    emit: Emit
    gate: PolicyGate | None = None
    backend: str = "offline"  # offline | claude
    pace: float = 0.0
    red_team: bool = False
    control: ControlPlane = field(default_factory=ControlPlane)
    proposals: list[Any] = field(default_factory=list)  # ActionRequest, filed via propose_action
    proposal_sink: Callable[[Any], dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        self.by_id = {e.id: e for e in self.events}
        self.by_actor: dict[str, list[Event]] = defaultdict(list)
        for e in self.events:
            self.by_actor[e.actor].append(e)

    def baseline_events(self, actor: str) -> list[Event]:
        return [e for e in self.by_actor.get(actor, []) if e.ts < self.window_start]

    def window_events(self) -> list[Event]:
        return [e for e in self.events if e.ts >= self.window_start]

    def source_of(self, event_id: str) -> str | None:
        e = self.by_id.get(event_id)
        return e.source.value if e else None

    async def tick(self, mult: float = 1.0) -> None:
        if self.pace:
            await asyncio.sleep(self.pace * mult)
