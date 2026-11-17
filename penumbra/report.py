"""Automated after-action briefing.

When the investigation closes, this compiles an executive brief from the
scratchpad, the approval cards and the audit trail, and writes the lessons
back into the Layer 2 knowledge store so the next investigation starts
smarter.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from .memory.knowledge import Doc


def build_brief(inv) -> str:
    ctx, sp, q = inv.ctx, inv.ctx.scratchpad, inv.queue
    verify = ctx.audit.verify()
    qv = Counter(r.verdict.value for r in ctx.quarantine.ledger.values())
    blocked = [r for r in ctx.audit.records if r["kind"] == "tool_blocked"]
    denied = [c for c in q.cards.values() if c.status == "denied_by_policy"]
    h = sp.hypothesis or {"statement": "No hypothesis reached.", "confidence": 0}

    L = [f"# After-Action Brief: {inv.id}",
         "",
         "> **SYNTHETIC EXERCISE.** Operation Low Tide, simulated environment (Halcyon Dynamics). "
         "All people, domains and accounts are fictional.",
         "",
         f"*Generated {datetime.now(UTC):%Y-%m-%d %H:%M} UTC · backend: `{ctx.backend}`"
         f"{' · RED-TEAM: quarantine disabled' if ctx.red_team else ''}*",
         "",
         "## Bottom line",
         f"{h['statement']}",
         "",
         f"**Confidence:** {h['confidence']:.2f}",
         "",
         "## Key judgments"]
    for f in sorted(sp.findings, key=lambda f: -f.confidence)[:8]:
        L.append(f"- **{f.title}** ({f.confidence:.2f}, {f.agent}): {f.detail}")
    L += ["", "## Attack timeline", "", "| Time | Actor | What happened | TTPs | Evidence |",
          "|---|---|---|---|---|"]
    for t in sp.timeline:
        L.append(f"| {t.ts[5:16].replace('T', ' ')} | {t.actor} | {t.summary} | "
                 f"{', '.join(t.ttps)} | {', '.join(t.evidence[:3])} |")
    ttps = Counter(t for f in sp.findings for t in f.ttps)
    L += ["", "## Technique mapping (MITRE ATT&CK / ATLAS)", "", "| ID | Technique | Findings |",
          "|---|---|---|"]
    for tid, n in sorted(ttps.items()):
        d = ctx.knowledge.get(tid)
        L.append(f"| {tid} | {d.title if d else ''} | {n} |")
    L += ["", "## Containment", "", "| Card | Action | Tier | Status | Approved by |",
          "|---|---|---|---|---|"]
    for c in q.cards.values():
        args = ", ".join(f"{v}" for v in c.request.args.values())
        L.append(f"| {c.id} | `{c.request.tool}({args})` | {c.tier.name} | {c.status} | "
                 f"{', '.join(a.approver for a in c.approvals) or '-'} |")
    if ctx.control.canaries:
        L += ["", "**Canaries deployed:** " + "; ".join(
            f"`{c['beacon_key']}` at {c['location']}" for c in ctx.control.canaries)]
    L += ["", "## Guardrail activity",
          f"- Quarantine processed {sum(qv.values())} untrusted payloads: "
          + ", ".join(f"{n} {v}" for v, n in qv.items()),
          f"- Prompt injections neutralized before reaching any model: {qv.get('malicious', 0)}",
          f"- Tool calls refused by scope guard: {len(blocked)}",
          f"- Proposals denied by the policy gate: {len(denied)}"
          + (" (" + "; ".join(f"{c.request.tool}: {', '.join(c.policy['rules'])}" for c in denied) + ")"
             if denied else ""),
          f"- Audit trail: {verify.records} signed records, chain "
          f"{'VERIFIED' if verify.ok else 'BROKEN at seq ' + str(verify.first_bad_seq)} "
          f"(Ed25519 pubkey `{ctx.audit.public_key_hex[:16]}…`)"]
    if sp.dismissed:
        L += ["", "## False positives suppressed"]
        L += [f"- **{d['subject']}**: {d['reason']}" for d in sp.dismissed]
    if sp.contradictions:
        L += ["", "## Contradiction checks"] + [f"- {c}" for c in sp.contradictions]
    L += ["", "## Recommended follow-up",
          "- HR + Legal interview of the subject before the last day; preserve evidence under hold.",
          "- Monitor canary beacons; feed any hit's source infrastructure back to OSINT.",
          "- Notify the other employees the persona targeted; report the persona to the platform.",
          "- Hunt for the persona's infrastructure (registrar/MX/ASN cluster) across mail logs.",
          "- Add detections: human `CreateAccessKey` on service accounts; cross-account bucket "
          "policies on scratch buckets.",
          ""]
    return "\n".join(L)


def learn(inv) -> Doc:
    sp = inv.ctx.scratchpad
    ttps = sorted({t for f in sp.findings for t in f.ttps})
    doc = Doc(f"INC-{inv.id}", f"Incident {inv.id} post-mortem",
              (sp.hypothesis or {}).get("statement", "") + " Techniques: " + ", ".join(ttps)
              + ". Lessons: watch human-minted service-account keys, cross-account bucket "
                "policies and AI-targeted injection in phishing.", kind="incident")
    inv.ctx.knowledge.add(doc)
    return doc
