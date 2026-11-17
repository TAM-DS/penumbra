"""Layer 2: the shared investigation scratchpad.

Several agents work one investigation at the same time. The scratchpad is
the single structured state they all read and write, so context survives
model handoffs. It's kept as structured data and rendered to Markdown for
humans and for LLM prompts. Agents can't overwrite one another; they can
only append findings that cite evidence.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    agent: str
    title: str
    detail: str
    confidence: float
    evidence: list[str]
    subjects: list[str] = field(default_factory=list)
    ttps: list[str] = field(default_factory=list)
    id: str = ""  # assigned by the scratchpad

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TimelineEntry:
    ts: str
    actor: str
    summary: str
    evidence: list[str]
    ttps: list[str] = field(default_factory=list)


class Scratchpad:
    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        self.findings: list[Finding] = []
        self.timeline: list[TimelineEntry] = []
        self.leads: list[dict[str, Any]] = []
        self.dismissed: list[dict[str, Any]] = []
        self.contradictions: list[str] = []
        self.hypothesis: dict[str, Any] | None = None
        self.status = "open"
        self._listeners: list[Callable[[str, dict], None]] = []

    def subscribe(self, fn: Callable[[str, dict], None]) -> None:
        self._listeners.append(fn)

    def _emit(self, kind: str, payload: dict) -> None:
        for fn in self._listeners:
            fn(kind, payload)

    def add_finding(self, f: Finding) -> Finding:
        if not f.evidence:
            raise ValueError("A finding must cite at least one evidence event ID.")
        f.id = f.id or f"F-{len(self.findings) + 1:03d}"
        self.findings.append(f)
        self._emit("finding", f.to_dict())
        return f

    def findings_about(self, subject: str) -> list[Finding]:
        return [f for f in self.findings if subject in f.subjects]

    def to_markdown(self) -> str:
        lines = [f"# Investigation {self.investigation_id} (status: {self.status})", ""]
        if self.hypothesis:
            lines += ["## Working hypothesis", f"{self.hypothesis['statement']} "
                      f"(confidence {self.hypothesis['confidence']:.2f})", ""]
        lines.append("## Leads")
        for lead in self.leads:
            lines.append(f"- **{lead['subject']}**: score {lead['score']:.2f}, {lead['reason']}")
        lines += ["", "## Findings"]
        for f in self.findings:
            lines.append(f"- [{f.id}] ({f.agent}, conf {f.confidence:.2f}) **{f.title}**: "
                         f"{f.detail} _evidence: {', '.join(f.evidence[:6])}_"
                         + (f" _TTPs: {', '.join(f.ttps)}_" if f.ttps else ""))
        if self.dismissed:
            lines += ["", "## Dismissed (false positives)"]
            for d in self.dismissed:
                lines.append(f"- {d['subject']}: {d['reason']}")
        if self.contradictions:
            lines += ["", "## Contradiction checks"] + [f"- {c}" for c in self.contradictions]
        return "\n".join(lines)
