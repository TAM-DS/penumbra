"""Command line: ``penumbra demo | serve | verify-audit | scenario``."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

C = {"triage": "36", "forensics": "33", "osint": "35", "deception": "32", "lead": "34"}
PH = {"think": "·", "act": "→", "observe": "←", "conclude": "■", "blocked": "✖"}


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if sys.stdout.isatty() else s


def _render(rec: dict, verbose: bool) -> None:
    t, d = rec["type"], rec["data"]
    if t == "step":
        if d["phase"] in ("act", "observe") and not verbose:
            return
        tag = _c(C.get(d["agent"], "37"), f"{d['agent']:>9}")
        text = d["text"] if len(d["text"]) < 240 or verbose else d["text"][:237] + "…"
        conf = f"  [{d['confidence']:.2f}]" if d.get("confidence") else ""
        style = "1;31" if d["phase"] == "blocked" else ("1" if d["phase"] == "conclude" else "0")
        print(f"{tag} {PH.get(d['phase'], ' ')} {_c(style, text)}{conf}")
    elif t == "quarantine" and d["verdict"] != "clean":
        print(_c("1;35", f"   QUARANTINE {d['event_id']}: {d['verdict'].upper()} "
                         f"({len(d['detections'])} detections; hidden directives stripped)"))
    elif t == "guardrail":
        print(_c("1;31", f"   GUARDRAIL[{d['layer']}] {d['tool']}: {d['reason']}"))
    elif t == "dismissed":
        print(_c("2", f"   dismissed {d['subject']}: {d['reason']}"))
    elif t == "card":
        if d["status"] in ("pending",) and not d["approvals"]:
            r = d["request"]
            print(_c("1;33", f"   CARD {d['id']} [{d['tier']}] {r['tool']}({', '.join(map(str, r['args'].values()))})")
                  + _c("2", f"  ↳ {d['blast_radius'].get('summary', '')}"))
        elif d["status"] == "executed":
            print(_c("1;32", f"   EXECUTED {d['id']} by {', '.join(a['approver'] for a in d['approvals'])}"))
        elif d["status"] == "denied_by_policy":
            print(_c("1;31", f"   DENIED {d['id']} {d['request']['tool']}: {', '.join(d['policy']['rules'])}"))
    elif t == "status":
        print(_c("1;37", f"\n== {d['status'].upper()} ==  ({d['investigation']}, backend={d['backend']}"
                         f"{', RED-TEAM' if d['red_team'] else ''})"))


async def _demo(args) -> int:
    from .engine import Investigation

    out = Path(args.out)
    inv = Investigation(backend=args.backend, red_team=args.red_team, pace=args.pace, runs_root=out)
    q = inv.subscribe()

    async def printer():
        while True:
            _render(await q.get(), args.verbose)

    p = asyncio.create_task(printer())
    await inv.run()
    await asyncio.sleep(0.05)
    approvers = ["lena.fischer", "alex.morgan"]
    for card in list(inv.queue.pending()):
        r = card.request
        if args.auto_approve:
            choice = "y"
        else:
            print(_c("1;33", f"\n{card.id} [{card.tier.name}] {r.tool}({r.args})"))
            print(f"  why:   {r.justification}\n  blast: {card.blast_radius.get('summary')}")
            choice = input("  approve? [y/N] ").strip().lower()
        if choice == "y":
            for who in approvers[:card.needed]:
                inv.approve(card.id, who)
        else:
            inv.reject(card.id, "operator", "declined at CLI")
        await asyncio.sleep(0.01)
    await asyncio.sleep(0.05)
    p.cancel()
    if inv.report:
        print("\n" + inv.report)
    v = inv.ctx.audit.verify()
    print(_c("1;32" if v.ok else "1;31",
             f"Audit chain: {v.records} records, {'VERIFIED' if v.ok else 'BROKEN'}. "
             f"Artifacts in {inv.run_dir}/"))
    return 0 if v.ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="penumbra", description="Agentic counterintelligence framework")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="run Operation Low Tide in the terminal")
    d.add_argument("--red-team", action="store_true",
                   help="disable the injection quarantine to prove defense in depth")
    d.add_argument("--auto-approve", action="store_true",
                   help="approve every card with simulated approvers (CI / headless)")
    d.add_argument("--backend", choices=["offline", "claude"], default=None,
                   help="default: claude if ANTHROPIC_API_KEY is set, else offline")
    d.add_argument("--pace", type=float, default=0.0)
    d.add_argument("--out", default="runs")
    d.add_argument("-v", "--verbose", action="store_true", help="show every tool call")
    s = sub.add_parser("serve", help="start the tactical workspace UI")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    va = sub.add_parser("verify-audit", help="verify a signed audit.jsonl")
    va.add_argument("path")
    sc = sub.add_parser("scenario", help="dump the synthetic telemetry as JSONL")
    sc.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)

    if args.cmd == "demo":
        return asyncio.run(_demo(args))
    if args.cmd == "serve":
        import uvicorn

        print(f"Penumbra tactical workspace → http://{args.host}:{args.port}")
        uvicorn.run("penumbra.server:app", host=args.host, port=args.port, log_level="warning")
        return 0
    if args.cmd == "verify-audit":
        from .guardrails.audit import verify_file

        v = verify_file(Path(args.path))
        print(json.dumps(v.__dict__))
        return 0 if v.ok else 1
    if args.cmd == "scenario":
        from .telemetry import generate

        for e in generate(args.seed):
            print(e.to_json())
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
