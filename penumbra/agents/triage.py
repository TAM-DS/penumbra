"""Triage & Router agent: separates signal from noise.

Fast and cheap by design (Haiku-class in Claude mode). It reads the
deterministic anomaly pre-filter, checks each candidate against business
context (HR travel, departures) and either escalates it to the
investigators or dismisses it with the reason written down. Every dismissal
is recorded: a false positive you can explain is worth as much as a true
positive.
"""

from __future__ import annotations

from ..telemetry import world
from .base import Agent

ESCALATE_AT = 0.4


class TriageAgent(Agent):
    name = "triage"
    title = "Triage & Router"
    tier = "fast"
    SYSTEM = """You are the Triage & Router agent. Call list_anomalies, then for each candidate
lead with score >= 0.4 check business context (hr_context, change_tickets). Escalate credible
leads with escalate_lead; dismiss explained anomalies with dismiss_lead and state the explaining
context. Pin escalated principals to the graph with pin_entity (risk = lead score). Be brief."""

    def task(self) -> str:
        return "Triage the detection window and route credible leads to the investigators."

    async def analyze(self):
        ctx = self.ctx
        n = len(ctx.window_events())
        await self.think(f"{n} telemetry events in the detection window. Running the baseline "
                         "pre-filter before spending any reasoning on them.")
        leads = await self.call("list_anomalies", threshold=0.2)
        flagged = sum(len(l["events"]) for l in leads)
        await self.think(f"Pre-filter kept {flagged} of {n} events ({flagged / n:.0%}), grouped "
                         f"into {len(leads)} candidate leads. Checking each against business context.")
        escalated = []
        for lead in leads:
            subj, score = lead["subject"], lead["score"]
            ev_ids = [e["event_id"] for e in lead["events"]]
            if score < ESCALATE_AT:
                await self.think(f"{subj}: {score:.2f} is below the escalation threshold. "
                                 "Leaving it on the watchlist.")
                continue
            if subj in world.EMPLOYEES:
                hr = await self.call("hr_context", user=subj)
                geo_only = all(all(r.startswith(("login from", "egress", "new device")) or
                                   " outside baseline hours" in r or "persona" in r
                                   for r in e["reasons"]) for e in lead["events"])
                login_cities = {ctx.by_id[i].attrs.get("city") for i in ev_ids
                                if ctx.by_id[i].kind == "login"}
                trip_cities = {t["city"] for t in hr.get("travel", [])}
                if geo_only and login_cities and login_cities <= trip_cities:
                    reason = (f"logins from {', '.join(sorted(login_cities))} match an approved "
                              f"HR travel record ({hr['travel'][0]['purpose']}); device is known; "
                              "no data access anomalies")
                    await self.think(f"{subj}: score {score:.2f}, but the context explains it: "
                                     f"{reason}. False positive.", confidence=0.9)
                    await self.call("dismiss_lead", subject=subj, reason=reason, evidence=ev_ids)
                    continue
                if hr.get("status") == "resignation_submitted":
                    await self.think(f"{subj} is a departing employee (last day "
                                     f"{hr.get('last_day')}). That raises insider-risk priority.")
            top = sorted({r for e in lead["events"] for r in e["reasons"]},
                         key=lambda r: -len(r))[:3]
            reason = f"{len(ev_ids)} anomalous events across {', '.join(lead['sources'])}: " + \
                     "; ".join(top)
            await self.call("escalate_lead", subject=subj, score=score, reason=reason,
                            evidence=ev_ids)
            ntype = "service_account" if subj in world.SERVICE_ACCOUNTS else "person"
            await self.call("pin_entity", id=subj, type=ntype, label=subj, risk=score)
            escalated.append(subj)
        await self.conclude(f"Escalated {len(escalated)} leads ({', '.join(escalated)}); "
                            f"dismissed {len(ctx.scratchpad.dismissed)} with recorded context.",
                            confidence=0.85)
        return escalated
