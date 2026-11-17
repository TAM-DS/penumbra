"""Deterministic anomaly scoring: the fast pre-filter in front of Triage.

Each event in the detection window is compared with its principal's
baseline, and every point of score comes with a human-readable reason. Leads
are aggregated per internal principal with a noisy-OR, so many weak signals
can add up to a credible lead while one weird event stays low.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..events import Event
from ..telemetry import world


def resolve_subject(e: Event) -> str:
    if e.actor in world.EMPLOYEES or e.actor in world.SERVICE_ACCOUNTS:
        return e.actor
    if e.target in world.EMPLOYEES or e.actor == "unknown":
        return e.target or e.actor
    return e.actor


def score_event(ctx, e: Event, baselines: dict[str, dict]) -> tuple[float, list[str]]:
    from .toolkit import profile_baseline

    b = baselines.setdefault(e.actor, profile_baseline(ctx, e.actor))
    r: list[tuple[float, str]] = []
    a = e.attrs
    hours = b.get("active_hours")
    off_hours = bool(hours) and not (hours[0] - 1 <= e.ts.hour <= hours[1] + 1)

    if e.kind == "login":
        if a.get("asn") not in b.get("asns", []):
            r.append((0.35, f"login from never-seen network {a.get('asn')} "
                            f"({world.ASN_INFO.get(a.get('asn'), {}).get('org', '?')})"))
        if world.ASN_INFO.get(a.get("asn"), {}).get("type") == "hosting/vpn":
            r.append((0.25, "egress is a hosting/VPN provider"))
        if a.get("new_device"):
            r.append((0.15, "new device"))
        if off_hours:
            r.append((0.2, f"{e.ts:%H:%M} is outside baseline hours {hours[0]}-{hours[1]}h"))
    elif e.kind == "repo_clone":
        if e.target not in b.get("repos", []):
            r.append((0.3, f"first-ever access to {e.target}"))
            if e.target in world.SENSITIVE_REPOS:
                r.append((0.25, "repo is crown-jewel tooling"))
        if off_hours:
            r.append((0.15, f"clone at {e.ts:%H:%M}"))
    elif e.kind == "CreateAccessKey":
        if e.actor in world.EMPLOYEES and e.target in world.SERVICE_ACCOUNTS:
            r.append((0.5, f"human minted a new key on service account {e.target}"))
        if "CreateAccessKey" not in b.get("iam_actions", []):
            r.append((0.15, "no IAM key history for this principal"))
        if off_hours:
            r.append((0.15, f"IAM change at {e.ts:%H:%M}"))
    elif e.kind in ("GetObject", "PutObject"):
        if a.get("access_key") not in b.get("access_keys", []):
            r.append((0.35, f"access key {a.get('access_key')} never seen before"))
        if e.target not in b.get("s3_prefixes", []) and any(
                e.target and e.target.startswith(p) and s == "crown_jewel"
                for p, s in world.SENSITIVE_PREFIXES.items()):
            r.append((0.2, "crown-jewel prefix (model checkpoints)"))
        mx = b.get("s3_max_bytes_per_event") or 1
        if a.get("bytes", 0) > 3 * mx:
            r.append((0.25, f"{a['bytes'] / 1e9:.1f} GB vs baseline max {mx / 1e9:.1f} GB"))
        if a.get("asn") and a.get("asn") not in b.get("asns", []):
            r.append((0.15, f"S3 calls from {a['asn']}"))
    elif e.kind == "PutBucketPolicy":
        if a.get("external_account") and a["external_account"] != world.CORP_AWS_ACCOUNT:
            r.append((0.6, f"bucket opened to external AWS account {a['external_account']}"))
    elif e.kind == "embedding_calls":
        mean = b.get("embedding_calls_mean") or 1
        ratio = a.get("count", 0) / mean
        if ratio > 10:
            r.append((0.5, f"{a['count']:,} embedding calls = {ratio:.0f}× baseline (model extraction pattern)"))
        if a.get("access_key") not in b.get("access_keys", []):
            r.append((0.2, "unfamiliar key on model gateway"))
    elif e.kind == "message" and a.get("external"):
        r.append((0.2, "Slack Connect message with an external party"))
        party = e.target if e.actor in world.EMPLOYEES else e.actor
        if party not in b.get("external_contacts", []):
            r.append((0.15, f"first-ever contact with {party}"))
        if e.content:
            q = ctx.quarantine.process(e.id, e.source.value, e.content)
            if q.verdict.value != "clean":
                r.append((0.4, f"content quarantine verdict: {q.verdict.value}"))
    elif e.kind == "inbound_email":
        q = ctx.quarantine.process(e.id, e.source.value, e.content or "")
        if q.verdict.value == "malicious":
            r.append((0.6, "email carries hidden instructions aimed at AI agents"))
        if q.indicators.get("link_mismatches"):
            r.append((0.2, "link text and destination don't match"))
        if a.get("sender_domain") not in world.CORP_DOMAINS and world.CORP_DOMAIN.split(".")[0] in a.get("sender_domain", ""):
            r.append((0.2, f"look-alike sender domain {a.get('sender_domain')}"))
    elif e.source.value == "osint":
        r.append((0.3, {"persona_contact": "external persona targeted this employee",
                        "paste_hit": "credentials found in a paste-site dump",
                        "domain_registered": "look-alike domain registered"}.get(e.kind, e.kind)))
    elif e.source.value == "hr" and a.get("status") == "resignation_submitted":
        r.append((0.2, "departing employee (resignation submitted)"))
    elif e.source.value == "dlp":
        r.append((0.1, f"DLP: {a.get('rule')} ({a.get('severity')})"))

    score = 0.0
    for w, _ in r:
        score = 1 - (1 - score) * (1 - w)
    return round(score, 3), [why for _, why in r]


def anomalies(ctx, threshold: float = 0.2) -> list[dict[str, Any]]:
    baselines: dict[str, dict] = {}
    out = []
    for e in ctx.window_events():
        s, why = score_event(ctx, e, baselines)
        if s >= threshold:
            out.append({"event_id": e.id, "ts": e.ts.isoformat(), "subject": resolve_subject(e),
                        "source": e.source.value, "kind": e.kind, "target": e.target,
                        "score": s, "reasons": why})
    return out


def aggregate_leads(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by: dict[str, list[dict]] = defaultdict(list)
    for it in items:
        by[it["subject"]].append(it)
    leads = []
    for subj, its in by.items():
        p = 0.0
        for it in its:
            p = 1 - (1 - p) * (1 - it["score"] * 0.6)  # damped: no single event convicts
        leads.append({"subject": subj, "score": round(p, 3), "events": its,
                      "sources": sorted({i["source"] for i in its})})
    return sorted(leads, key=lambda x: -x["score"])
