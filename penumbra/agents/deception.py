"""Deception & Countermeasure agent.

Designs active-defense moves: canary documents, honeytokens and decoy
credentials placed where the adversary is already looking. It *proposes*
them. Deploying anything goes through the policy gate and a human.

A canary placed in the staging bucket the insider just opened to an outside
account turns exfiltration into attribution: if the external party reads
and uses the decoy key, it beacons with their infrastructure.
"""

from __future__ import annotations

from .base import Agent


class DeceptionAgent(Agent):
    name = "deception"
    title = "Deception & Countermeasures"
    SYSTEM = """You are the Deception & Countermeasure agent. Using the graph and scratchpad,
find where the adversary is collecting or staging data, then design a canary or honeytoken
that blends in there and would beacon if used. Check simulate_blast_radius, then
propose_action(deploy_canary) citing evidence from at least two telemetry sources. Never
propose anything that could harm a real person or production system."""

    def task(self) -> str:
        return "Design and propose a deception countermeasure for the active staging location."

    async def analyze(self):
        ctx = self.ctx
        g = ctx.graph
        staging = [n for n in g.nodes.values() if n.type == "bucket" and "scratch" in n.id]
        if not staging:
            await self.conclude("No staging location identified; nothing to bait.")
            return
        bucket = staging[0].id
        nb = await self.call("graph_neighbors", node_id=bucket)
        ext = [x["node"]["id"] for x in nb if x["node"].get("type") == "external_account"]
        evidence = sorted({ev for x in nb for ev in x["edge"]["evidence"]})
        await self.think(f"{bucket} is the staging point" +
                         (f" and is readable by external account {ext[0]}" if ext else "") +
                         ". The adversary will pull from it within the access window. A decoy "
                         "here is guaranteed to be seen.")
        await self.call("search_knowledge", query="canary honeytoken deception exfiltration staging")
        await self.think("Design: a 'manifest-final.json' that matches the staged checkpoint "
                         "naming. It embeds a canary AWS key and a DNS beacon. If the outside "
                         "party loads the manifest and tries the key, we get their source "
                         "infrastructure and a timestamp. It contains no real data.")
        sim = await self.call("simulate_blast_radius", tool="deploy_canary", target=f"{bucket}/staging/")
        slack = [f.evidence[0] for f in ctx.scratchpad.findings if "staged" in f.title.lower()
                 and ctx.source_of(f.evidence[0]) == "slack"]
        res = await self.call("propose_action", tool="deploy_canary",
                              args={"location": f"{bucket}/staging/", "kind": "aws_key_manifest"},
                              justification="Staging bucket is exposed to an external account; a "
                                            "beaconing decoy gives attribution on access with no "
                                            "production impact. " + sim["summary"],
                              evidence=evidence[:4] + slack[:1], confidence=0.9)
        await self.conclude(f"Canary proposed ({res.get('status', 'queued')}).", confidence=0.9)
