"""Behavioral & Insider Forensics agent.

Starts from an escalated principal, compares what they did with their own
baseline, and follows the credentials: when a human mints a key on a service
account, the agent pivots to everything that key did afterwards. That's how
a "service account anomaly" and a "user anomaly" turn out to be one actor.
"""

from __future__ import annotations

from ..telemetry import world
from .base import Agent


class ForensicsAgent(Agent):
    name = "forensics"
    title = "Behavioral & Insider Forensics"
    SYSTEM = """You are the Behavioral & Insider Forensics agent. For each escalated human lead:
compare window activity to get_baseline, follow any credentials they created (query_events with
attr_equals='access_key=...') to everything those credentials touched, check change_tickets for
authorization, and map behaviors to ATT&CK/ATLAS (search_knowledge). Pin entities and link them
with timestamps and evidence. Record one finding per distinct behavior."""

    def task(self) -> str:
        leads = [l["subject"] for l in self.ctx.scratchpad.leads if l["subject"] in world.EMPLOYEES]
        return f"Investigate these escalated principals: {leads}."

    async def analyze(self):
        ctx = self.ctx
        for lead in [l for l in ctx.scratchpad.leads if l["subject"] in world.EMPLOYEES]:
            user = lead["subject"]
            own = [i for i in lead["evidence"] if ctx.by_id[i].actor == user
                   and ctx.by_id[i].source.value not in ("hr", "osint", "email")]
            if not own:
                await self.think(f"{user}: none of the anomalous events were performed by "
                                 f"{user}. They're a target here, not an actor, so I'm leaving "
                                 "them to OSINT.")
                continue
            acts = await self.call("query_events", actor=user)
            await self.investigate(user, [a for a in acts if a["source"] != "hr"])

    async def investigate(self, user: str, acts: list[dict]):
        base = await self.call("get_baseline", actor=user)
        await self.think(f"Baseline for {user}: active {base['active_hours'][0]}-"
                         f"{base['active_hours'][1]}h, networks {base['asns']}, repos "
                         f"{base['repos']}, IAM history {base['iam_actions'] or 'none'}.")

        logins = [a for a in acts if a["kind"] == "login" and a["attrs"]["asn"] not in base["asns"]]
        if logins:
            lg = logins[0]
            asn = lg["attrs"]["asn"]
            await self.call("pin_entity", id=asn, type="asn",
                            label=f"{asn} {world.ASN_INFO.get(asn, {}).get('org', '')}", risk=0.6)
            await self.call("pin_entity", id=lg["attrs"]["device_id"], type="device",
                            label=lg["attrs"]["device_id"], risk=0.5)
            await self.call("link_entities", src=user, dst=asn, rel="logged_in_from", ts=lg["ts"],
                            evidence=[lg["id"]])
            await self.call("link_entities", src=user, dst=lg["attrs"]["device_id"],
                            rel="used_device", ts=lg["ts"], evidence=[lg["id"]])
            await self.call("record_finding", title="Off-hours login from VPN egress on a new device",
                            detail=f"{lg['ts'][11:16]} login via {asn} "
                                   f"({world.ASN_INFO.get(asn, {}).get('type')}) from "
                                   f"{lg['attrs']['city']} on unseen device {lg['attrs']['device_id']}; "
                                   "MFA push was approved.",
                            confidence=0.8, evidence=[lg["id"]], subjects=[user],
                            ttps=["T1078.004"])

        clones = [a for a in acts if a["kind"] == "repo_clone" and a["target"] not in base["repos"]]
        if clones:
            for c in clones:
                await self.call("pin_entity", id=c["target"], type="repo", label=c["target"],
                                risk=0.6 if c["target"] in world.SENSITIVE_REPOS else 0.3)
                await self.call("link_entities", src=user, dst=c["target"], rel="cloned",
                                ts=c["ts"], evidence=[c["id"]])
            gb = sum(c["attrs"]["bytes"] for c in clones) / 1e9
            await self.call("record_finding", title="First-ever clones of checkpoint tooling",
                            detail=f"{len(clones)} repos never touched in the baseline "
                                   f"({', '.join(c['target'] for c in clones)}), {gb:.1f} GB, "
                                   "minutes after the anomalous login.",
                            confidence=0.75, evidence=[c["id"] for c in clones], subjects=[user],
                            ttps=["T1213.003"])

        for mk in [a for a in acts if a["kind"] == "CreateAccessKey"]:
            sa, key = mk["target"], mk["attrs"]["new_access_key"]
            await self.think(f"{user} minted access key {key} on service account {sa}. A human "
                             "creating credentials on a pipeline identity is a classic way to "
                             "launder attribution. Checking whether a change was approved.")
            tickets = await self.call("change_tickets", target=sa)
            recent = [t for t in tickets if t["date"] >= self.ctx.window_start.date().isoformat()]
            await self.think(f"{len(tickets)} ticket(s) on record for {sa}, "
                             f"{len(recent)} in the window. The key creation is unsanctioned."
                             if not recent else "A change ticket exists; lowering severity.")
            await self.call("pin_entity", id=sa, type="service_account", label=sa, risk=0.7)
            await self.call("pin_entity", id=key, type="access_key", label=key, risk=0.9)
            await self.call("link_entities", src=user, dst=key, rel="minted", ts=mk["ts"],
                            evidence=[mk["id"]])
            await self.call("link_entities", src=key, dst=sa, rel="credential_of", ts=mk["ts"],
                            evidence=[mk["id"]])
            await self.call("record_finding", title=f"Unsanctioned access key minted on {sa}",
                            detail=f"{key} created at {mk['ts'][11:16]} with no change ticket. "
                                   f"{user} has no IAM key history.",
                            confidence=0.85, evidence=[mk["id"]], subjects=[user, sa],
                            ttps=["T1098.001"])
            await self.follow_key(user, sa, key, mk["id"])

        pol = [a for a in acts if a["kind"] == "PutBucketPolicy"]
        for p in pol:
            acct = p["attrs"]["external_account"]
            intel = await self.call("lookup_threat_intel", indicator=acct)
            await self.call("pin_entity", id=p["target"], type="bucket", label=p["target"], risk=0.8)
            await self.call("pin_entity", id=acct, type="external_account",
                            label=f"AWS {acct}", risk=0.9)
            await self.call("link_entities", src=user, dst=p["target"], rel="opened_policy",
                            ts=p["ts"], evidence=[p["id"]])
            await self.call("link_entities", src=p["target"], dst=acct, rel="readable_by",
                            ts=p["ts"], evidence=[p["id"]])
            await self.call("record_finding", title="Staging bucket opened to an external AWS account",
                            detail=f"{user} granted {acct} access to {p['target']}. Threat intel: "
                                   f"{', '.join(intel['tags']) or 'no tags'}. Data can leave without "
                                   "egress traffic crossing our perimeter.",
                            confidence=0.9, evidence=[p["id"]], subjects=[user, acct],
                            ttps=["T1537"])

        hr = await self.call("hr_context", user=user)
        if hr.get("status") == "resignation_submitted":
            hr_ev = [e.id for e in self.ctx.by_actor[user] if e.source.value == "hr"]
            await self.call("record_finding", title="Resignation submitted: departure window opens",
                            detail=f"Resignation submitted {hr.get('since')}, last day "
                                   f"{hr.get('last_day')}. All of the collection happened in this window.",
                            confidence=0.6, evidence=hr_ev, subjects=[user], ttps=["INS-DEPARTING"])
        chain = [f.title.split(" ")[0].lower() for f in self.ctx.scratchpad.findings
                 if f.agent == self.name and user in f.subjects]
        await self.conclude(f"{user}: {len(chain)} linked behaviors, from the off-hours login to "
                            "the key mint, bulk read, staging and external grant. One actor working "
                            "through a laundered service identity.", confidence=0.88)

    async def follow_key(self, user: str, sa: str, key: str, mint_id: str):
        used = await self.call("query_events", attr_equals=f"access_key={key}")
        await self.think(f"Pivoting on {key}: {len(used)} events used it after creation.")
        reads = [u for u in used if u["kind"] == "GetObject"]
        if reads:
            prefix = reads[0]["target"]
            gb = sum(r["attrs"]["bytes"] for r in reads) / 1e9
            objs = sum(r["attrs"]["count"] for r in reads)
            base = await self.call("get_baseline", actor=sa)
            await self.call("pin_entity", id=prefix, type="bucket", label=prefix, risk=0.8)
            await self.call("link_entities", src=key, dst=prefix, rel="bulk_read",
                            ts=reads[0]["ts"], evidence=[r["id"] for r in reads])
            await self.call("record_finding", title="Bulk read of model checkpoints",
                            detail=f"{objs} objects / {gb:.1f} GB from {prefix} in "
                                   f"{len(reads)} bursts. The service's nightly sync moves at most "
                                   f"{base['s3_max_bytes_per_event'] / 1e9:.1f} GB with key "
                                   f"{base['access_keys'][0]}.",
                            confidence=0.9, evidence=[r["id"] for r in reads],
                            subjects=[user, sa], ttps=["T1530"])
        emb = [u for u in used if u["kind"] == "embedding_calls"]
        if emb:
            e = emb[0]
            base = await self.call("get_baseline", actor=sa)
            ratio = e["attrs"]["count"] / max(1, base["embedding_calls_mean"])
            await self.call("pin_entity", id=e["target"], type="model", label=e["target"], risk=0.7)
            await self.call("link_entities", src=key, dst=e["target"], rel="scraped", ts=e["ts"],
                            evidence=[e["id"]])
            await self.call("record_finding", title="Embedding extraction through the model gateway",
                            detail=f"{e['attrs']['count']:,} calls in {e['attrs']['window_min']} min "
                                   f"({ratio:.0f}× baseline): consistent with model-behavior "
                                   "extraction.",
                            confidence=0.8, evidence=[e["id"]], subjects=[user, sa],
                            ttps=["AML.T0024"])
        puts = [u for u in used if u["kind"] == "PutObject"]
        if puts:
            p = puts[0]
            bucket = p["target"].split("/staging")[0]
            await self.call("pin_entity", id=bucket, type="bucket", label=bucket, risk=0.85)
            await self.call("link_entities", src=key, dst=bucket, rel="staged_to", ts=p["ts"],
                            evidence=[p["id"]])
            await self.call("record_finding", title="Checkpoints staged in a personal scratch bucket",
                            detail=f"{p['attrs']['count']} objects / {p['attrs']['bytes'] / 1e9:.1f} GB "
                                   f"written to {p['target']}.",
                            confidence=0.85, evidence=[p["id"]], subjects=[user, sa],
                            ttps=["T1074.002"])
