"""The tool surface: every capability an agent or the executor can use.

Handlers are bound to one ``InvestigationContext``. The offline analytic
agents and the Claude-driven agents call the *same* registry through the
*same* scope checks, so swapping in a frontier model changes the reasoning,
not the security boundary.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from ..context import InvestigationContext
from ..guardrails import ActionRequest, Scope, Tier, Tool, ToolRegistry
from ..memory.scratchpad import Finding, TimelineEntry
from ..telemetry import world

S = {"type": "string"}
N = {"type": "number"}
I = {"type": "integer"}
A = {"type": "array", "items": {"type": "string"}}


# ---------------------------------------------------------------- analytics
def profile_baseline(ctx: InvestigationContext, actor: str) -> dict[str, Any]:
    ev = ctx.baseline_events(actor)
    if not ev:
        return {"actor": actor, "events": 0, "note": "no baseline history"}
    hours = [e.ts.hour for e in ev if e.source.value in ("okta", "github", "cloudtrail")]
    days = max(1, len({e.ts.date() for e in ev}))
    s3 = [e for e in ev if e.kind == "GetObject"]
    emb = [e.attrs.get("count", 0) for e in ev if e.kind == "embedding_calls"]
    return {
        "actor": actor,
        "events": len(ev),
        "active_hours": [min(hours), max(hours)] if hours else None,
        "asns": sorted({e.attrs["asn"] for e in ev if "asn" in e.attrs}),
        "devices": sorted({e.attrs["device_id"] for e in ev if "device_id" in e.attrs}),
        "repos": sorted({e.target for e in ev if e.kind == "repo_clone"}),
        "max_clone_bytes": max([e.attrs.get("bytes", 0) for e in ev if e.kind == "repo_clone"] or [0]),
        "iam_actions": sorted({e.kind for e in ev if e.kind in
                               ("CreateAccessKey", "PutBucketPolicy", "AttachUserPolicy")}),
        "access_keys": sorted({e.attrs["access_key"] for e in ev if "access_key" in e.attrs}),
        "s3_prefixes": sorted({e.target for e in s3}),
        "s3_max_bytes_per_event": max([e.attrs.get("bytes", 0) for e in s3] or [0]),
        "embedding_calls_mean": round(sum(emb) / len(emb)) if emb else 0,
        "external_contacts": sorted({e.target for e in ev if e.attrs.get("external")}),
        "days_observed": days,
    }


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def domain_analysis(domain: str, as_of: date) -> dict[str, Any]:
    d = domain.lower()
    w = world.lookup_whois(d)
    stem = d.split(".")[0]
    nearest = min(world.CORP_DOMAINS, key=lambda c: levenshtein(d, c))
    dist = levenshtein(d, nearest)
    stems = {c.split(".")[0] for c in world.CORP_DOMAINS}
    lookalike = d not in world.CORP_DOMAINS and not any(d.endswith("." + c) for c in world.CORP_DOMAINS) \
        and (dist <= 4 or any(cs in stem or stem in cs for cs in stems))
    out = {"domain": d, "whois": w, "nearest_corp_domain": nearest, "edit_distance": dist,
           "lookalike": lookalike, "is_corporate": d in world.CORP_DOMAINS}
    if "registered" in w:
        out["age_days"] = (as_of - date.fromisoformat(w["registered"])).days
    return out


def _as_of(ctx: InvestigationContext) -> date:
    return ctx.events[-1].ts.date()


# ---------------------------------------------------------------- registry
def build_registry(ctx: InvestigationContext) -> ToolRegistry:
    reg = ToolRegistry()
    g, sp = ctx.graph, ctx.scratchpad

    # ---------------- READ
    def query_events(actor: str | None = None, source: str | None = None, kind: str | None = None,
                     target_contains: str | None = None, attr_equals: str | None = None,
                     window_only: bool = True, limit: int = 60) -> list[dict]:
        pool = ctx.window_events() if window_only else ctx.events
        out = []
        for e in pool:
            if actor and e.actor != actor:
                continue
            if source and e.source.value != source:
                continue
            if kind and e.kind != kind:
                continue
            if target_contains and target_contains not in (e.target or ""):
                continue
            if attr_equals:
                k, _, v = attr_equals.partition("=")
                if str(e.attrs.get(k)) != v:
                    continue
            out.append(e.metadata_view())
        return out[:limit]

    def read_content(event_id: str) -> dict:
        e = ctx.by_id.get(event_id)
        if not e or not e.content:
            return {"error": "no untrusted content on this event"}
        r = ctx.quarantine.ledger.get(event_id) or ctx.quarantine.process(
            event_id, e.source.value, e.content)
        out = {"verdict": r.verdict.value, "score": r.score, "indicators": r.indicators,
               "detections": [{"technique": d.technique, "channel": d.channel} for d in r.detections],
               "content": r.envelope()}
        ctx.emit("quarantine", {"event_id": event_id, "source": e.source.value,
                                "verdict": r.verdict.value, "score": r.score,
                                "detections": [d.__dict__ for d in r.detections],
                                "indicators": r.indicators,
                                "sanitized_preview": r.sanitized_text[:400],
                                "red_team": ctx.red_team})
        ctx.audit.append("quarantine", "quarantine_verdict",
                         {"event_id": event_id, "verdict": r.verdict.value, "score": r.score,
                          "original_sha256": r.original_sha256,
                          "detections": [d.technique for d in r.detections]})
        return out

    reg.register(Tool("query_events", "Query normalized telemetry metadata (never raw content). "
                      "Filters: actor, source, kind, target_contains, attr_equals ('key=value').",
                      Scope.READ, {"actor": S, "source": S, "kind": S, "target_contains": S,
                                   "attr_equals": S, "window_only": {"type": "boolean"},
                                   "limit": I}, handler=query_events))
    reg.register(Tool("get_baseline", "Behavioral baseline for a principal from the pre-incident "
                      "window: hours, ASNs, devices, repos, IAM actions, data volumes.",
                      Scope.READ, {"actor": S}, ("actor",),
                      handler=lambda actor: profile_baseline(ctx, actor)))
    reg.register(Tool("read_content", "Read the untrusted text of an event. Always returned "
                      "quarantined: sanitized, spotlighted, with injection verdict and indicators.",
                      Scope.READ, {"event_id": S}, ("event_id",), handler=read_content))
    reg.register(Tool("lookup_domain", "WHOIS, age and look-alike analysis for a domain "
                      "(simulated OSINT feed).", Scope.READ, {"domain": S}, ("domain",),
                      handler=lambda domain: domain_analysis(domain, _as_of(ctx))))
    reg.register(Tool("lookup_persona", "Profile analysis for an external identity: account age, "
                      "activity, synthetic-avatar score, who they target (simulated feed).",
                      Scope.READ, {"handle": S}, ("handle",), handler=world.lookup_persona))
    reg.register(Tool("lookup_threat_intel", "Threat-intel tags for an ASN, IP or account ID.",
                      Scope.READ, {"indicator": S}, ("indicator",), handler=world.lookup_threat_intel))
    reg.register(Tool("hr_context", "HR context for an employee: status, travel, title.",
                      Scope.READ, {"user": S}, ("user",),
                      handler=lambda user: {**world.HR_RECORDS.get(user, {"status": "active",
                                                                           "travel": []}),
                                            "title": getattr(world.EMPLOYEES.get(user), "title", None),
                                            "protected": getattr(world.EMPLOYEES.get(user),
                                                                 "protected", False)}))
    reg.register(Tool("change_tickets", "Approved change tickets mentioning a target.",
                      Scope.READ, {"target": S}, ("target",),
                      handler=lambda target: [t for t in world.CHANGE_TICKETS
                                              if target in (t["target"], t["requester"])]))
    def list_anomalies(threshold: float = 0.2) -> list[dict]:
        from .scoring import aggregate_leads, anomalies
        leads = aggregate_leads(anomalies(ctx, threshold))
        return [{"subject": l["subject"], "score": l["score"], "sources": l["sources"],
                 "events": [{k: ev[k] for k in ("event_id", "ts", "kind", "score", "reasons")}
                            for ev in l["events"]]} for l in leads]

    reg.register(Tool("list_anomalies", "Deterministic pre-filter: window events scored against "
                      "each principal's baseline, grouped into candidate leads.", Scope.READ,
                      {"threshold": N}, handler=list_anomalies))
    reg.register(Tool("search_knowledge", "Search threat TTPs (ATT&CK / ATLAS), policies and past "
                      "incident post-mortems.", Scope.READ, {"query": S, "k": I}, ("query",),
                      handler=lambda query, k=3: ctx.knowledge.search(query, k)))
    reg.register(Tool("graph_neighbors", "Entities and time-stamped relations around a graph node.",
                      Scope.READ, {"node_id": S}, ("node_id",), handler=g.neighbors))
    reg.register(Tool("read_scratchpad", "Read the shared investigation scratchpad (Markdown).",
                      Scope.READ, handler=sp.to_markdown))

    def simulate(tool: str, target: str) -> dict:
        from ..hitl.blast_radius import simulate as sim
        return sim(ctx, tool, target)

    reg.register(Tool("simulate_blast_radius", "Counterfactual: predict what breaks if a "
                      "containment action is executed.", Scope.READ, {"tool": S, "target": S},
                      ("tool", "target"), handler=simulate))

    # ---------------- NOTE
    def record_finding(title: str, detail: str, confidence: float, evidence: list[str],
                       subjects: list[str] | None = None, ttps: list[str] | None = None,
                       _agent: str = "agent") -> dict:
        bad = [e for e in evidence if e not in ctx.by_id]
        if bad:
            return {"error": f"unknown evidence ids {bad}: findings must cite real events"}
        f = sp.add_finding(Finding(_agent, title, detail, float(confidence), evidence,
                                   subjects or [], ttps or []))
        return {"recorded": f.id}

    def pin_entity(id: str, type: str, label: str | None = None, risk: float = 0.0,
                   first_seen: str | None = None) -> dict:
        g.upsert_node(id, type, label, risk=risk, ts=first_seen)
        return {"pinned": id}

    def link_entities(src: str, dst: str, rel: str, ts: str | None = None,
                      evidence: list[str] | None = None, _agent: str = "agent") -> dict:
        for n in (src, dst):
            if n not in g.nodes:
                return {"error": f"pin '{n}' first"}
        g.add_edge(src, dst, rel, ts=ts, evidence=evidence, asserted_by=_agent)
        return {"linked": f"{src} -{rel}-> {dst}"}

    def escalate_lead(subject: str, score: float, reason: str, evidence: list[str]) -> dict:
        sp.leads.append({"subject": subject, "score": score, "reason": reason, "evidence": evidence})
        ctx.emit("lead", sp.leads[-1])
        return {"escalated": subject}

    def dismiss_lead(subject: str, reason: str, evidence: list[str]) -> dict:
        sp.dismissed.append({"subject": subject, "reason": reason, "evidence": evidence})
        ctx.emit("dismissed", sp.dismissed[-1])
        return {"dismissed": subject}

    def add_timeline_entry(ts: str, actor: str, summary: str, evidence: list[str],
                           ttps: list[str] | None = None) -> dict:
        sp.timeline.append(TimelineEntry(ts, actor, summary, evidence, ttps or []))
        sp.timeline.sort(key=lambda t: t.ts)
        ctx.emit("timeline", {"ts": ts, "actor": actor, "summary": summary, "evidence": evidence,
                              "ttps": ttps or []})
        return {"ok": True}

    def set_hypothesis(statement: str, confidence: float, evidence: list[str]) -> dict:
        sp.hypothesis = {"statement": statement, "confidence": confidence, "evidence": evidence}
        ctx.emit("hypothesis", sp.hypothesis)
        return {"ok": True}

    def record_contradiction_check(check: str) -> dict:
        sp.contradictions.append(check)
        return {"ok": True}

    for t in [
        Tool("record_finding", "Append an evidence-backed finding to the shared scratchpad.",
             Scope.NOTE, {"title": S, "detail": S, "confidence": N, "evidence": A,
                          "subjects": A, "ttps": A},
             ("title", "detail", "confidence", "evidence"), handler=record_finding),
        Tool("pin_entity", "Pin an entity to the evidence graph (person, service_account, "
             "access_key, repo, bucket, domain, persona, asn, external_account, model, canary, "
             "injection).", Scope.NOTE, {"id": S, "type": S, "label": S, "risk": N,
                                         "first_seen": S}, ("id", "type"), handler=pin_entity),
        Tool("link_entities", "Add a time-stamped, evidence-backed relation between two pinned "
             "entities.", Scope.NOTE, {"src": S, "dst": S, "rel": S, "ts": S, "evidence": A},
             ("src", "dst", "rel"), handler=link_entities),
        Tool("escalate_lead", "Escalate a principal as a credible lead for investigation.",
             Scope.NOTE, {"subject": S, "score": N, "reason": S, "evidence": A},
             ("subject", "score", "reason", "evidence"), handler=escalate_lead),
        Tool("dismiss_lead", "Dismiss an anomaly as a false positive, with the context that "
             "explains it.", Scope.NOTE, {"subject": S, "reason": S, "evidence": A},
             ("subject", "reason", "evidence"), handler=dismiss_lead),
        Tool("add_timeline_entry", "Add an entry to the attack timeline.", Scope.NOTE,
             {"ts": S, "actor": S, "summary": S, "evidence": A, "ttps": A},
             ("ts", "actor", "summary", "evidence"), handler=add_timeline_entry),
        Tool("set_hypothesis", "Set the working hypothesis for the investigation.", Scope.NOTE,
             {"statement": S, "confidence": N, "evidence": A},
             ("statement", "confidence", "evidence"), handler=set_hypothesis),
        Tool("record_contradiction_check", "Record a check made against the hypothesis "
             "and its outcome.", Scope.NOTE, {"check": S}, ("check",),
             handler=record_contradiction_check),
    ]:
        reg.register(t)

    # ---------------- PROPOSE
    def propose_action(tool: str, args: dict, justification: str, evidence: list[str],
                       confidence: float, target_principal: str | None = None,
                       _agent: str = "agent") -> dict:
        req = ActionRequest(tool, args, _agent, justification, evidence, float(confidence),
                            target_principal)
        if ctx.proposal_sink is None:
            ctx.proposals.append(req)
            return {"queued": req.id}
        return ctx.proposal_sink(req)

    reg.register(Tool("propose_action", "Propose a containment action. This doesn't execute "
                      "anything: it files a request that passes the deterministic policy gate "
                      "and then waits for human approval.", Scope.PROPOSE,
                      {"tool": S, "args": {"type": "object"}, "justification": S,
                       "evidence": A, "confidence": N, "target_principal": S},
                      ("tool", "args", "justification", "evidence", "confidence"),
                      handler=propose_action))

    # ---------------- CONTAIN (executor service only)
    cp = ctx.control

    def _contained(node_id: str, label: str) -> None:
        if node_id in g.nodes:
            g.upsert_node(node_id, g.nodes[node_id].type, contained=label)

    def revoke_access_key(access_key: str) -> dict:
        cp.revoked_keys.add(access_key)
        _contained(access_key, "revoked")
        return {"revoked": access_key}

    def remove_bucket_policy(bucket: str) -> dict:
        cp.removed_bucket_policies.add(bucket)
        _contained(bucket, "external grant removed")
        return {"policy_removed": bucket}

    def force_mfa_reauth(user: str) -> dict:
        cp.mfa_reset_users.add(user)
        _contained(user, "sessions revoked + MFA re-enroll")
        return {"mfa_reset": user}

    def block_domain(domain: str) -> dict:
        cp.blocked_domains.add(domain)
        _contained(domain, "blocked at mail + web gateway")
        return {"blocked": domain}

    def suspend_user(user: str) -> dict:
        cp.suspended_users.add(user)
        _contained(user, "suspended")
        return {"suspended": user}

    def deploy_canary(location: str, kind: str) -> dict:
        token = f"AKIACANARY{len(cp.canaries) + 1:04d}PNBR"
        c = {"location": location, "kind": kind, "beacon_key": token,
             "deployed_at": datetime.now().isoformat(timespec="seconds")}
        cp.canaries.append(c)
        node = f"canary:{token}"
        g.upsert_node(node, "canary", f"canary {kind}", risk=0.0, beacon=token)
        if location.rstrip("/").split("/staging")[0] in g.nodes:
            g.add_edge(node, location.rstrip("/").split("/staging")[0], "planted_in",
                       asserted_by="executor")
        return c

    def isolate_endpoint(device_id: str) -> dict:
        _contained(device_id, "isolated")
        return {"isolated": device_id}

    for name, desc, params, req, h, tier in [
        ("revoke_access_key", "Deactivate one IAM access key.", {"access_key": S}, ("access_key",),
         revoke_access_key, Tier.SINGLE),
        ("remove_bucket_policy", "Remove a bucket policy granting external access.",
         {"bucket": S}, ("bucket",), remove_bucket_policy, Tier.SINGLE),
        ("force_mfa_reauth", "Revoke sessions and force MFA re-enrollment.", {"user": S},
         ("user",), force_mfa_reauth, Tier.SINGLE),
        ("block_domain", "Block a domain at mail and web gateways.", {"domain": S}, ("domain",),
         block_domain, Tier.SINGLE),
        ("deploy_canary", "Plant a honeytoken / canary document that beacons on use.",
         {"location": S, "kind": S}, ("location", "kind"), deploy_canary, Tier.SINGLE),
        ("suspend_user", "Suspend an employee account.", {"user": S}, ("user",), suspend_user,
         Tier.DUAL),
        ("isolate_endpoint", "Network-isolate a managed endpoint.", {"device_id": S},
         ("device_id",), isolate_endpoint, Tier.DUAL),
    ]:
        reg.register(Tool(name, desc, Scope.CONTAIN, params, req, handler=h, tier=tier))

    # ---------------- PROHIBITED: registered by name so they can be refused by name.
    for name, desc in [
        ("wipe_endpoint", "Erase a device."),
        ("delete_data", "Delete stored data."),
        ("disable_logging", "Turn off a log source."),
        ("delete_audit_log", "Remove audit records."),
        ("allowlist_domain", "Mark a domain as trusted."),
        ("close_investigation", "Close the investigation."),
    ]:
        reg.register(Tool(name, desc, Scope.PROHIBITED, {"target": S}, irreversible=True))

    ctx.quarantine.tool_names |= set(reg.tools)
    return reg

