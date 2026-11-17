"""Lead Investigator (the orchestrator's synthesis step).

Reads everything the sub-agents produced, cross-correlates across them
(the step no single specialist can do), runs explicit contradiction checks
against the leading hypothesis, builds the attack timeline and drafts a
containment plan made of the *narrowest effective* actions. Every action
it drafts is only a proposal: the policy gate and the humans decide.
"""

from __future__ import annotations

from ..telemetry import world
from .base import Agent


class LeadInvestigator(Agent):
    name = "lead"
    title = "Lead Investigator"
    tier = "deep"
    SYSTEM = """You are the Lead Investigator. Read the scratchpad and graph. Cross-correlate
findings from different agents (shared infrastructure, shared identities, timing). Run explicit
contradiction checks (travel, change tickets, account-takeover vs insider) and record each with
record_contradiction_check. Build the timeline with add_timeline_entry, set the hypothesis with
calibrated confidence, then draft a containment plan: use simulate_blast_radius and prefer the
narrowest reversible action, then propose_action for each step, citing ≥2 telemetry sources."""

    def task(self) -> str:
        return "Synthesize the investigation, test the hypothesis, build the timeline and propose containment."

    async def analyze(self):
        ctx, sp, g = self.ctx, self.ctx.scratchpad, self.ctx.graph
        await self.call("read_scratchpad")
        await self.think(f"{len(sp.findings)} findings from "
                         f"{len({f.agent for f in sp.findings})} agents. Looking for links that "
                         "no single agent could see.")

        # ---- cross-agent correlation: shared hosting ASN
        asn_links = {}
        for n in [n for n in g.nodes.values() if n.type == "asn"]:
            nb = await self.call("graph_neighbors", node_id=n.id)
            people = [x for x in nb if x["node"].get("type") == "person"]
            domains = [x for x in nb if x["node"].get("type") == "domain"]
            if people and domains:
                asn_links[n.id] = (people, domains)
        for asn, (people, domains) in asn_links.items():
            ev = sorted({e for x in people + domains for e in x["edge"]["evidence"]})
            await self.call("record_finding", title="Insider session and attacker infrastructure share a network",
                            detail=f"{people[0]['node']['id']}'s 02:11 session egressed from {asn}, the "
                                   f"same hosting ASN as {', '.join(d['node']['id'] for d in domains)}. "
                                   "Forensics and OSINT found these independently.",
                            confidence=0.8, evidence=ev[:6],
                            subjects=[people[0]["node"]["id"]] + [d["node"]["id"] for d in domains],
                            ttps=["T1078.004", "T1583.001"])

        insider = next((l["subject"] for l in sp.leads if l["subject"] in world.EMPLOYEES and
                        any(f.agent == "forensics" for f in sp.findings_about(l["subject"]))), None)
        if not insider:
            await self.conclude("No actor identified; recommending monitoring only.")
            return

        # ---- contradiction checks
        hr = await self.call("hr_context", user=insider)
        await self.call("record_contradiction_check",
                        check=f"Travel explains the Bucharest login? HR shows "
                              f"{len(hr.get('travel', []))} trips for {insider}. Not explained.")
        sa = next((n.id for n in g.nodes.values() if n.type == "service_account"), None)
        if sa:
            t = await self.call("change_tickets", target=sa)
            await self.call("record_contradiction_check",
                            check=f"Sanctioned key rotation on {sa}? Last ticket "
                                  f"{t[-1]['id'] if t else 'none'} ({t[-1]['date'] if t else '-'}) by "
                                  f"{t[-1]['requester'] if t else '-'}. Nothing covers the 02:19 key. Not explained.")
        await self.think("Main alternative: account takeover. An outsider with stolen credentials "
                         "could produce the same telemetry. Against it: the Slack 'staged' message "
                         "goes to a persona that spent weeks cultivating this person, the activity "
                         "falls inside the resignation window, and MFA was approved. For it: new "
                         "device, VPN egress. Insider collusion is more likely, but ATO isn't ruled "
                         "out. Containment should cut access without assuming guilt.",
                         confidence=0.8)
        await self.call("record_contradiction_check",
                        check="Account takeover vs insider: insider collusion favored (~0.85); "
                              "ATO not excluded, so the plan uses session revocation before "
                              "suspension, and HR/Legal own the interview.")

        # ---- timeline
        seen = set()
        for f in sorted(sp.findings, key=lambda f: min(ctx.by_id[e].ts for e in f.evidence)):
            first = min(f.evidence, key=lambda e: ctx.by_id[e].ts)
            if f.title in seen or f.agent == self.name:  # analysis, not an event
                continue
            seen.add(f.title)
            await self.call("add_timeline_entry", ts=ctx.by_id[first].ts.isoformat(),
                            actor=", ".join(f.subjects[:2]) or f.agent, summary=f.title,
                            evidence=f.evidence[:4], ttps=f.ttps)

        all_ev = sorted({e for f in sp.findings for e in f.evidence})
        ext = next((n.id for n in g.nodes.values() if n.type == "external_account"), "an external account")
        persona = next((n for n in g.nodes.values() if n.type == "persona"), None)
        statement = (f"Departing employee {insider}, cultivated by synthetic persona "
                     f"{persona.label.replace(' (persona)', '') if persona else 'unknown'}, used a laundered service-account "
                     f"key to bulk-copy model checkpoints and scrape embeddings, then staged them for "
                     f"{ext}. A parallel spear-phish carried an AI-targeted injection meant to get "
                     f"this investigation closed. The adversary expects AI defenders.")
        await self.call("set_hypothesis", statement=statement, confidence=0.86, evidence=all_ev[:12])

        # ---- containment plan
        await self.think("Containment order: (1) close the exfil path, (2) kill the laundered "
                         "credential, (3) cut live sessions, (4) protect the phished admin, (5) burn "
                         "attacker infrastructure, (6) suspension, which needs two people. "
                         "Blast radius first for anything touching production.")
        ev = lambda *pred: [f.evidence for f in sp.findings if any(p in f.title.lower() for p in pred)]
        flat = lambda lists: sorted({e for l in lists for e in l})

        bucket = next((n.id for n in g.nodes.values() if n.type == "bucket" and "scratch" in n.id), None)
        if bucket:
            await self.propose("remove_bucket_policy", {"bucket": bucket},
                               "Exfil path is open now. Removing the cross-account grant stops the "
                               "external pull immediately.",
                               flat(ev("external aws", "staged")), 0.92)
        key = next((n.id for n in g.nodes.values() if n.type == "access_key"), None)
        if key:
            sim = await self.call("simulate_blast_radius", tool="revoke_access_key", target=key)
            await self.think(f"Counterfactual: {sim['summary']} "
                             + (sim["alternatives"][0] if sim["alternatives"] else ""))
            await self.propose("revoke_access_key", {"access_key": key},
                               "Laundered key used for the bulk read, embedding scrape and staging. "
                               + sim["summary"], flat(ev("access key", "embedding", "bulk read")), 0.93)
        await self.propose("force_mfa_reauth", {"user": insider},
                           "Revoke live sessions on the unrecognized device. Reversible, and correct "
                           "whether this is insider action or account takeover.",
                           flat(ev("off-hours login", "external aws")), 0.88, target=insider)
        victims = [f.subjects[0] for f in sp.findings if "paste dump" in f.title]
        for v in victims:
            await self.propose("force_mfa_reauth", {"user": v},
                               f"{v} was spear-phished and has leaked credentials in a paste dump.",
                               flat(ev("paste dump", "spear-phish", "credential-phishing")), 0.8, target=v)
        for d in sorted(n.id for n in g.nodes.values() if n.type == "domain"):
            await self.propose("block_domain", {"domain": d},
                               f"{d} is part of the attacker's look-alike infrastructure.",
                               flat(ev("look-alike", "persona", "spear-phish")), 0.9)
        sim = await self.call("simulate_blast_radius", tool="suspend_user", target=insider)
        await self.propose("suspend_user", {"user": insider},
                           "Full suspension pending HR/Legal interview. " + sim["summary"],
                           flat(ev("off-hours", "access key", "external aws", "staged")), 0.86,
                           target=insider)
        await self.conclude("Hypothesis set (0.86). Containment plan filed to the approval queue. "
                            "Nothing executes without the policy gate and a human.",
                            confidence=0.86)

    async def propose(self, tool, args, why, evidence, conf, target=None):
        kw = dict(tool=tool, args=args, justification=why, evidence=evidence[:8], confidence=conf)
        if target:
            kw["target_principal"] = target
        return await self.call("propose_action", **kw)
