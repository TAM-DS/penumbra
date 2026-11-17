"""Tactical workspace API: FastAPI + Server-Sent Events.

    penumbra serve              # http://localhost:8000

The UI is static HTML/JS served from ``penumbra/ui``, so there's no build
step: clone, install, run.
"""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .engine import Investigation, default_backend
from .guardrails.audit import verify_records
from .telemetry import world

UI = Path(__file__).parent / "ui"
app = FastAPI(title="Penumbra", version="0.1.0")
app.mount("/static", StaticFiles(directory=UI), name="static")

STATE: dict[str, Any] = {"inv": None, "task": None}


class StartReq(BaseModel):
    red_team: bool = False
    pace: float = 0.35
    backend: str | None = None


class ApproveReq(BaseModel):
    approver: str
    role: str = "security"


class RejectReq(BaseModel):
    approver: str
    reason: str = ""


def _inv() -> Investigation:
    inv = STATE["inv"]
    if inv is None:
        raise HTTPException(404, "no investigation running; POST /api/investigations")
    return inv


@app.get("/")
def index() -> FileResponse:
    return FileResponse(UI / "index.html")


@app.get("/api/config")
def config() -> dict:
    return {"default_backend": default_backend(),
            "approvers": [{"id": k, "role": v} for k, v in world.AUTHORIZED_APPROVERS.items()]}


@app.post("/api/investigations")
async def start(req: StartReq) -> dict:
    if STATE["task"] and not STATE["task"].done():
        STATE["task"].cancel()
    inv = Investigation(backend=req.backend, red_team=req.red_team,
                        pace=max(0.0, min(req.pace, 2.0)), runs_root=Path("runs"))
    STATE["inv"] = inv
    STATE["task"] = asyncio.create_task(inv.run())
    return {"id": inv.id, "backend": inv.ctx.backend, "red_team": req.red_team}


@app.get("/api/stream")
async def stream(inv_id: str | None = None) -> StreamingResponse:
    inv = _inv()
    if inv_id and inv.id != inv_id:
        raise HTTPException(409, "investigation changed")
    q = inv.subscribe()

    async def gen():
        try:
            while True:
                try:
                    rec = await asyncio.wait_for(q.get(), timeout=15)
                    yield f"data: {json.dumps(rec, default=str)}\n\n"
                except TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            inv.subscribers.discard(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/state")
def state() -> dict:
    inv = _inv()
    sp = inv.ctx.scratchpad
    return {"id": inv.id, "status": inv.status, "backend": inv.ctx.backend,
            "red_team": inv.ctx.red_team, "graph": inv.ctx.graph.snapshot(),
            "cards": [c.to_dict() for c in inv.queue.cards.values()],
            "findings": [f.to_dict() for f in sp.findings], "hypothesis": sp.hypothesis,
            "scratchpad": sp.to_markdown()}


@app.post("/api/cards/{card_id}/approve")
def approve(card_id: str, req: ApproveReq) -> dict:
    try:
        return _inv().approve(card_id, req.approver, req.role)
    except (KeyError, ValueError) as e:
        raise HTTPException(400, str(e)) from e


@app.post("/api/cards/{card_id}/reject")
def reject(card_id: str, req: RejectReq) -> dict:
    try:
        return _inv().reject(card_id, req.approver, req.reason)
    except KeyError as e:
        raise HTTPException(400, str(e)) from e


@app.get("/api/report", response_class=PlainTextResponse)
def report() -> str:
    inv = _inv()
    return inv.report or "Report is generated when every approval card is resolved."


@app.get("/api/audit")
def audit(limit: int = 400) -> dict:
    a = _inv().ctx.audit
    v = a.verify()
    return {"verify": v.__dict__, "public_key": a.public_key_hex, "records": a.records[-limit:]}


@app.post("/api/audit/tamper-test")
def tamper_test() -> dict:
    """Demonstration only: alter a *copy* of the log and show verification fail."""
    a = _inv().ctx.audit
    recs = copy.deepcopy(a.records)
    target = next((r for r in recs if r["kind"] == "tool_call"), None)
    if target is None:
        raise HTTPException(400, "no records yet")
    target["payload"]["args"] = {"tampered": True}
    v = verify_records(recs, a.public_key_hex)
    return {"tampered_seq": target["seq"], "verify": v.__dict__}
