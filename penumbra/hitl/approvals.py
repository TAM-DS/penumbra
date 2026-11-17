"""Layer 5: human-in-the-loop approvals and the isolated executor.

Confidence-based escalation:

* ``AUTO``: enrichment and reads, which agents do on their own.
* ``SINGLE``: medium-risk containment; one authorized human clicks Approve.
* ``DUAL``: high-risk; two *distinct* authorized humans, neither of them
  the proposing agent.

Every proposal is first simulated (blast radius), then evaluated by the
policy gate, and only then shown as a tactical approval card. On approval
the **executor**, the only component holding ``CONTAIN`` scope,
re-evaluates the gate with the approvals attached and runs the action.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..context import InvestigationContext
from ..guardrails import EXECUTOR_SCOPES, ActionRequest, Approval, PolicyGate, Tier
from .blast_radius import simulate


@dataclass
class Card:
    request: ActionRequest
    tier: Tier
    policy: dict[str, Any]
    blast_radius: dict[str, Any]
    status: str  # pending | denied_by_policy | rejected | executed | failed
    approvals: list[Approval] = field(default_factory=list)
    result: Any = None
    id: str = ""
    created: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def needed(self) -> int:
        return {Tier.AUTO: 0, Tier.SINGLE: 1, Tier.DUAL: 2}.get(self.tier, 0)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "status": self.status, "tier": self.tier.name,
                "needed": self.needed, "request": self.request.to_dict(),
                "policy": self.policy, "blast_radius": self.blast_radius,
                "approvals": [a.__dict__ for a in self.approvals], "result": self.result,
                "created": self.created}


class ApprovalQueue:
    def __init__(self, ctx: InvestigationContext, gate: PolicyGate) -> None:
        self.ctx = ctx
        self.gate = gate
        self.cards: dict[str, Card] = {}

    def executed_count(self) -> int:
        return sum(1 for c in self.cards.values() if c.status in ("pending", "executed"))

    def submit(self, req: ActionRequest) -> dict[str, Any]:
        target = next(iter(req.args.values()), "") if req.args else ""
        req.blast_radius = simulate(self.ctx, req.tool, str(target))
        decision = self.gate.evaluate(req)
        self.ctx.audit.append("policy_gate", "policy_decision",
                              {"request": req.to_dict(), "decision": decision.to_dict()},
                              model="deterministic-policy")
        if not decision.allowed:
            card = Card(req, Tier.BLOCKED, decision.to_dict(), req.blast_radius, "denied_by_policy")
            self.ctx.emit("guardrail", {"layer": "policy", "agent": req.proposed_by,
                                        "tool": req.tool, "reason": "; ".join(decision.reasons),
                                        "rules": decision.rules})
        else:
            card = Card(req, decision.tier, decision.to_dict(), req.blast_radius, "pending")
        card.id = f"CARD-{len(self.cards) + 1:03d}"
        self.cards[card.id] = card
        self.ctx.emit("card", card.to_dict())
        return {"card": card.id, "status": card.status, "tier": card.tier.name,
                "policy": decision.reasons}

    def pending(self) -> list[Card]:
        return [c for c in self.cards.values() if c.status == "pending"]

    def approve(self, card_id: str, approver: str, role: str = "security") -> Card:
        card = self.cards[card_id]
        if card.status != "pending":
            raise ValueError(f"{card_id} is {card.status}")
        if any(a.approver == approver for a in card.approvals):
            raise ValueError(f"{approver} already approved {card_id}; two-person rule needs "
                             "a different approver")
        card.approvals.append(Approval(approver, role))
        self.ctx.audit.append(f"human:{approver}", "approval",
                              {"card": card_id, "tool": card.request.tool,
                               "args": card.request.args, "approvals": len(card.approvals),
                               "needed": card.needed})
        if len(card.approvals) >= card.needed:
            self._execute(card)
        self.ctx.emit("card", card.to_dict())
        return card

    def reject(self, card_id: str, approver: str, reason: str = "") -> Card:
        card = self.cards[card_id]
        card.status = "rejected"
        card.result = {"rejected_by": approver, "reason": reason}
        self.ctx.audit.append(f"human:{approver}", "rejection", {"card": card_id, "reason": reason})
        self.ctx.emit("card", card.to_dict())
        return card

    def _execute(self, card: Card) -> None:
        d = self.gate.evaluate(card.request, card.approvals, at_execution=True)
        self.ctx.audit.append("policy_gate", "policy_decision_execution",
                              {"card": card.id, "decision": d.to_dict()},
                              model="deterministic-policy")
        if not d.allowed:
            card.status = "failed"
            card.result = {"error": "; ".join(d.reasons)}
            return
        try:
            card.result = self.ctx.registry.invoke(card.request.tool, card.request.args,
                                                   EXECUTOR_SCOPES, caller="executor")
            card.status = "executed"
        except Exception as e:  # pragma: no cover - defensive
            card.status = "failed"
            card.result = {"error": str(e)}
        self.ctx.audit.append("executor", "execution",
                              {"card": card.id, "tool": card.request.tool,
                               "args": card.request.args, "status": card.status,
                               "result": card.result,
                               "approvers": [a.approver for a in card.approvals]},
                              model="executor-service")
