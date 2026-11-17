"""The investigation engine: wires the five layers together and runs the
Manager-Worker graph.

    telemetry ─► event bus ─► Triage ─┬─► Forensics ─┐
                                       └─► OSINT ─────┴─► Deception ─► Lead
                                                                        │
                    approval cards ◄── policy gate ◄── proposals ◄──────┘
                          │
                     human(s) ─► policy gate (again) ─► executor ─► after-action brief

The graph is lean on purpose: plain asyncio and structured tool calls, with no
agent framework in the trust path, so every hop can be read and audited.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .agents.deception import DeceptionAgent
from .agents.forensics import ForensicsAgent
from .agents.lead import LeadInvestigator
from .agents.osint import OsintAgent
from .agents.toolkit import build_registry
from .agents.triage import TriageAgent
from .context import InvestigationContext
from .events import EventBus
from .guardrails import AuditLog, PolicyContext, PolicyGate, Quarantine, ToolRegistry
from .hitl.approvals import ApprovalQueue
from .memory import KnowledgeStore, Scratchpad, TemporalGraph
from .report import build_brief, learn
from .telemetry import generate, world
from .telemetry.scenario import WINDOW_START


def default_backend() -> str:
    return "claude" if os.environ.get("ANTHROPIC_API_KEY") else "offline"


class Investigation:
    def __init__(self, backend: str | None = None, red_team: bool = False, pace: float = 0.0,
                 seed: int = 7, run_dir: Path | None = None, runs_root: Path | None = None) -> None:
        self.id = "INV-" + datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        if runs_root is not None and run_dir is None:
            run_dir = Path(runs_root) / self.id
        self.status = "created"
        self.log: list[dict[str, Any]] = []
        self.subscribers: set[asyncio.Queue] = set()
        self.report: str | None = None
        self.run_dir = run_dir
        if run_dir:
            run_dir.mkdir(parents=True, exist_ok=True)

        events = generate(seed)
        principals = set(world.EMPLOYEES) | set(world.SERVICE_ACCOUNTS)
        self.ctx = InvestigationContext(
            investigation_id=self.id, events=events, window_start=WINDOW_START,
            graph=TemporalGraph(), scratchpad=Scratchpad(self.id), knowledge=KnowledgeStore(),
            quarantine=Quarantine(enabled=not red_team, known_principals=principals),
            registry=ToolRegistry(), audit=AuditLog(run_dir / "audit.jsonl" if run_dir else None),
            emit=self.emit, backend=backend or default_backend(), pace=pace, red_team=red_team)
        self.ctx.registry = build_registry(self.ctx)
        self.gate = PolicyGate(PolicyContext(
            registry=self.ctx.registry, is_tainted=self.ctx.quarantine.is_tainted,
            source_of=self.ctx.source_of,
            protected_principals={u for u, e in world.EMPLOYEES.items() if e.protected},
            authorized_approvers=world.AUTHORIZED_APPROVERS,
            containment_count=lambda: self.queue.executed_count()))
        self.ctx.gate = self.gate
        self.queue = ApprovalQueue(self.ctx, self.gate)
        self.ctx.proposal_sink = self.queue.submit
        self.ctx.graph.subscribe(lambda k, p: self.emit(f"graph_{k}", p))
        self.ctx.scratchpad.subscribe(lambda k, p: self.emit(k, p))

    # ------------------------------------------------------------------ stream
    def emit(self, type: str, data: dict[str, Any]) -> None:
        rec = {"seq": len(self.log), "type": type,
               "ts": datetime.now(UTC).isoformat(timespec="milliseconds"), "data": data}
        self.log.append(rec)
        for q in list(self.subscribers):
            q.put_nowait(rec)

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        for rec in self.log:
            q.put_nowait(rec)
        self.subscribers.add(q)
        return q

    def _set_status(self, s: str) -> None:
        self.status = s
        self.emit("status", {"status": s, "investigation": self.id, "backend": self.ctx.backend,
                             "red_team": self.ctx.red_team})

    # ------------------------------------------------------------------ run
    async def ingest(self) -> None:
        self._set_status("ingesting")
        bus = EventBus()
        await bus.publish_many(self.ctx.events)
        await bus.close()
        counts: dict[str, int] = {}
        n = 0
        async for e in bus.consume():
            n += 1
            counts[e.source.value] = counts.get(e.source.value, 0) + 1
            if n % 120 == 0 or n == len(self.ctx.events):
                self.emit("radar", {"ingested": n, "total": len(self.ctx.events),
                                    "by_source": dict(counts),
                                    "window_events": len(self.ctx.window_events())})
                await self.ctx.tick(0.5)

    async def run(self) -> None:
        try:
            await self.ingest()
            self._set_status("investigating")
            await TriageAgent(self.ctx).run()
            await asyncio.gather(ForensicsAgent(self.ctx).run(), OsintAgent(self.ctx).run())
            await DeceptionAgent(self.ctx).run()
            await LeadInvestigator(self.ctx).run()
            self.emit("trust", self.trust_scores())
            if self.queue.pending():
                self._set_status("awaiting_approval")
            else:
                self.finalize()
        except Exception as e:  # surface failures to the UI rather than dying silently
            self.emit("error", {"message": f"{type(e).__name__}: {e}"})
            self._set_status("error")
            raise

    def trust_scores(self) -> dict[str, float]:
        """Entity trust = 1 − max(risk) across the graph (shown on the radar)."""
        return {n.id: round(1 - n.risk, 2) for n in self.ctx.graph.nodes.values()
                if n.type in ("person", "service_account", "persona", "domain")}

    # ------------------------------------------------------------------ humans
    def approve(self, card_id: str, approver: str, role: str = "security") -> dict:
        c = self.queue.approve(card_id, approver, role)
        self._maybe_close()
        return c.to_dict()

    def reject(self, card_id: str, approver: str, reason: str = "") -> dict:
        c = self.queue.reject(card_id, approver, reason)
        self._maybe_close()
        return c.to_dict()

    def _maybe_close(self) -> None:
        if self.status == "awaiting_approval" and not self.queue.pending():
            self.finalize()

    def finalize(self) -> str:
        self.ctx.scratchpad.status = "closed"
        self.report = build_brief(self)
        doc = learn(self)
        self.emit("learned", {"doc": doc.id, "title": doc.title})
        self.emit("report", {"markdown": self.report})
        if self.run_dir:
            (self.run_dir / "report.md").write_text(self.report)
            (self.run_dir / "scratchpad.md").write_text(self.ctx.scratchpad.to_markdown())
            (self.run_dir / "graph.json").write_text(json.dumps(self.ctx.graph.snapshot(), indent=1))
        self._set_status("closed")
        return self.report
