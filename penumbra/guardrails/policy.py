"""Layer 4d: the deterministic policy gate.

No LLM output takes effect in the world without going through this
hard-coded rules engine. The engine doesn't read prose, doesn't take
instructions and can't be persuaded. Each rule is a small pure function
with a stable ID, so every allow or deny can be explained and audited, and
the rule set can be mirrored in Open Policy Agent
(``policies/penumbra.rego``) for organizations that centralize policy
there.

The gate runs **twice** for every containment action: when the agent
proposes it (to set the approval tier) and again at execution time, with
the approvals attached. That second check closes the time-of-check /
time-of-use gap.
"""

from __future__ import annotations

import itertools
import json
import os
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from .tools import Scope, Tier, ToolRegistry

_ids = itertools.count(1)

MAX_CONTAINMENT_ACTIONS = 12
MIN_CONFIDENCE = 0.7
MIN_EVIDENCE_SOURCES = 2

# Tools that make the defender *weaker*. Only humans, through change
# management, may ever do these.
DEFENSE_WEAKENING = {"allowlist_domain", "close_investigation", "disable_logging",
                     "unblock_ip", "delete_audit_log", "suppress_alert"}


@dataclass
class ActionRequest:
    tool: str
    args: dict[str, Any]
    proposed_by: str
    justification: str
    evidence: list[str]
    confidence: float
    target_principal: str | None = None
    blast_radius: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: f"ACT-{next(_ids):03d}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Approval:
    approver: str
    role: str


@dataclass
class Decision:
    allowed: bool
    tier: Tier
    reasons: list[str]
    rules: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "tier": self.tier.name, "reasons": self.reasons,
                "rules": self.rules}


@dataclass
class PolicyContext:
    registry: ToolRegistry
    is_tainted: Callable[[str], bool]
    source_of: Callable[[str], str | None]
    protected_principals: set[str]
    authorized_approvers: dict[str, str]  # approver -> role
    containment_count: Callable[[], int] = lambda: 0


class PolicyGate:
    def __init__(self, ctx: PolicyContext) -> None:
        self.ctx = ctx

    def evaluate(self, req: ActionRequest, approvals: list[Approval] | None = None,
                 at_execution: bool = False) -> Decision:
        reasons: list[str] = []
        rules: list[str] = []
        deny = False
        tool = self.ctx.registry.get(req.tool)

        def no(rule: str, why: str) -> None:
            nonlocal deny
            deny = True
            rules.append(rule)
            reasons.append(why)

        # P-001: tool must exist.
        if tool is None:
            no("P-001", f"unknown tool '{req.tool}'")
            return Decision(False, Tier.BLOCKED, reasons, rules)

        # P-002: irreversible / prohibited tools are never agent-executable.
        if tool.scope is Scope.PROHIBITED or tool.irreversible:
            no("P-002", f"'{req.tool}' is prohibited: irreversible or destructive actions "
                        "can't be executed by any agent")

        # P-003: defense-weakening actions are human-only.
        if req.tool in DEFENSE_WEAKENING:
            no("P-003", f"'{req.tool}' weakens defenses; only a human, through change "
                        "management, may do this")

        # P-004: only CONTAIN-scope tools go through the approval pipeline.
        if tool.scope not in (Scope.CONTAIN, Scope.PROHIBITED):
            no("P-004", f"'{req.tool}' isn't a containment tool")

        # P-005: tainted provenance. An action can't be justified *only* by
        # events whose content tried to manipulate the agent. (A tainted event's
        # metadata, e.g. "an email from X reached Y", is still fact from our
        # own gateway, so it counts toward corroboration below. Its content
        # never counts.)
        if req.evidence and all(self.ctx.is_tainted(e) for e in req.evidence):
            no("P-005", "every cited evidence event carries a prompt-injection taint; "
                        "an action can't rest solely on adversary-controlled content")

        # P-006: corroboration. Containment needs independent signals.
        if tool.scope is Scope.CONTAIN:
            sources = {self.ctx.source_of(e) for e in req.evidence} - {None}
            if len(sources) < MIN_EVIDENCE_SOURCES:
                no("P-006", f"needs evidence from ≥{MIN_EVIDENCE_SOURCES} independent telemetry "
                            f"sources (has {len(sources)})")
            if req.confidence < MIN_CONFIDENCE:
                no("P-007", f"confidence {req.confidence:.2f} below threshold {MIN_CONFIDENCE}")

        # P-008: schema.
        try:
            tool.validate(req.args)
        except ValueError as e:
            no("P-008", str(e))

        # P-009: containment rate limit per investigation.
        if not at_execution and self.ctx.containment_count() >= MAX_CONTAINMENT_ACTIONS:
            no("P-009", "containment action budget for this investigation is exhausted")

        # ---- tier assignment (only meaningful if allowed)
        tier = tool.tier
        if req.target_principal and req.target_principal in self.ctx.protected_principals:
            tier = max(tier, Tier.DUAL)
            rules.append("T-001")
            reasons.append(f"{req.target_principal} is a protected principal → two-person sign-off")
        pipelines = req.blast_radius.get("pipelines_halted", [])
        if len(pipelines) >= 5:
            tier = max(tier, Tier.DUAL)
            rules.append("T-002")
            reasons.append(f"blast radius halts {len(pipelines)} pipelines → two-person sign-off")
        if tool.scope is Scope.CONTAIN and tier is Tier.AUTO:
            tier = Tier.SINGLE  # T-003: containment is never fully autonomous
            rules.append("T-003")

        # ---- execution-time checks
        if at_execution and not deny:
            approvals = approvals or []
            valid = [a for a in approvals if self.ctx.authorized_approvers.get(a.approver) == a.role]
            distinct = {a.approver for a in valid if a.approver != req.proposed_by}
            if len(valid) != len(approvals):
                no("E-001", "one or more approvers aren't authorized")
            need = {Tier.AUTO: 0, Tier.SINGLE: 1, Tier.DUAL: 2}.get(tier, 99)
            if len(distinct) < need:
                no("E-002", f"tier {tier.name} needs {need} distinct authorized approver(s); "
                            f"has {len(distinct)}")

        if deny:
            return Decision(False, Tier.BLOCKED, reasons, rules)
        reasons.insert(0, f"allowed at tier {tier.name}")
        return Decision(True, tier, reasons, rules)


class OPAPolicyGate(PolicyGate):  # pragma: no cover - requires an OPA server
    """Delegates the allow/deny decision to Open Policy Agent, then *also*
    applies the built-in rules. Either one can deny."""

    def __init__(self, ctx: PolicyContext, url: str | None = None) -> None:
        super().__init__(ctx)
        self.url = url or os.environ["PENUMBRA_OPA_URL"]  # e.g. http://localhost:8181

    def evaluate(self, req, approvals=None, at_execution=False):
        local = super().evaluate(req, approvals, at_execution)
        body = json.dumps({"input": {"request": req.to_dict(), "at_execution": at_execution,
                                     "tainted": [e for e in req.evidence if self.ctx.is_tainted(e)]}})
        r = urllib.request.urlopen(urllib.request.Request(
            f"{self.url}/v1/data/penumbra/decision", body.encode(),
            {"Content-Type": "application/json"}), timeout=3)
        opa = json.loads(r.read()).get("result", {})
        if not opa.get("allow", False):
            return Decision(False, Tier.BLOCKED, local.reasons + opa.get("deny", ["OPA denied"]),
                            local.rules + ["OPA"])
        return local
