from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from penumbra.guardrails import Tier
from penumbra.guardrails.audit import verify_file

from .conftest import run_inv


def test_triage_escalates_insider_and_dismisses_travel_decoy(closed_inv):
    sp = closed_inv.ctx.scratchpad
    leads = {l["subject"] for l in sp.leads}
    assert {"dana.reyes", "svc-ml-batch"} <= leads
    assert "jon.alvarez" not in leads  # big clones, but in his baseline
    assert [d["subject"] for d in sp.dismissed] == ["ruth.kim"]


def test_findings_cover_the_kill_chain(closed_inv):
    ttps = {t for f in closed_inv.ctx.scratchpad.findings for t in f.ttps}
    assert {"T1078.004", "T1213.003", "T1098.001", "T1530", "AML.T0024", "T1074.002", "T1537",
            "T1585.001", "T1583.001", "AML.T0051", "T1566.002"} <= ttps


def test_every_finding_cites_real_events(closed_inv):
    ids = closed_inv.ctx.by_id
    for f in closed_inv.ctx.scratchpad.findings:
        assert f.evidence and all(e in ids for e in f.evidence)


def test_cross_agent_correlation_found_shared_asn(closed_inv):
    titles = [f.title for f in closed_inv.ctx.scratchpad.findings if f.agent == "lead"]
    assert any("share a network" in t for t in titles)


def test_injection_names_the_insider(closed_inv):
    f = next(f for f in closed_inv.ctx.scratchpad.findings if "AML.T0051" in f.ttps)
    assert "dana.reyes" in f.subjects


def test_containment_plan_is_surgical_and_tiered(closed_inv):
    cards = {(c.request.tool, next(iter(c.request.args.values()))): c for c in closed_inv.queue.cards.values()}
    assert cards[("revoke_access_key", "AKIASVCMLBATCH7Q2X")].blast_radius["pipelines_halted"] == []
    assert cards[("suspend_user", "dana.reyes")].tier is Tier.DUAL
    assert ("remove_bucket_policy", "s3://halcyon-scratch-dana") in cards
    assert ("deploy_canary", "s3://halcyon-scratch-dana/staging/") in cards
    assert all(c.status == "pending" for c in closed_inv.queue.cards.values())
    assert closed_inv.status == "awaiting_approval"
    assert not closed_inv.ctx.control.revoked_keys  # nothing executed without a human


def test_full_approval_closes_with_verified_audit(tmp_path):
    inv = run_inv(run_dir=tmp_path)
    for c in list(inv.queue.pending()):
        inv.approve(c.id, "lena.fischer")
        if c.needed == 2:
            inv.approve(c.id, "alex.morgan")
    assert inv.status == "closed"
    cp = inv.ctx.control
    assert "AKIASVCMLBATCH7Q2X" in cp.revoked_keys and "dana.reyes" in cp.suspended_users
    assert cp.canaries and cp.canaries[0]["beacon_key"].startswith("AKIACANARY")
    assert "VERIFIED" in inv.report and "Operation Low Tide" in inv.report
    assert (tmp_path / "report.md").exists() and (tmp_path / "audit.pub").exists()
    assert inv.ctx.knowledge.get(f"INC-{inv.id}") is not None  # lessons written back


def test_rejection_is_respected():
    inv = run_inv()
    c = next(c for c in inv.queue.pending() if c.request.tool == "suspend_user")
    inv.reject(c.id, "lena.fischer", "HR wants interview first")
    assert "dana.reyes" not in inv.ctx.control.suspended_users


def test_red_team_hijack_is_contained_by_code_not_by_the_model():
    inv = run_inv(red_team=True)
    blocked = [r for r in inv.ctx.audit.records if r["kind"] == "tool_blocked"]
    assert {r["payload"]["tool"] for r in blocked} >= {"allowlist_domain"}
    denied = {c.request.tool: c for c in inv.queue.cards.values() if c.status == "denied_by_policy"}
    assert {"allowlist_domain", "close_investigation"} <= set(denied)
    assert "P-003" in denied["allowlist_domain"].policy["rules"]
    # and the investigation still reached the right conclusion
    assert inv.ctx.scratchpad.hypothesis and "dana.reyes" in inv.ctx.scratchpad.hypothesis["statement"]


def test_deterministic_across_runs():
    a, b = run_inv(), run_inv()
    assert [f.title for f in a.ctx.scratchpad.findings] == [f.title for f in b.ctx.scratchpad.findings]


def test_same_second_investigations_preserve_both_audits(tmp_path):
    with patch("penumbra.engine.datetime", wraps=datetime) as clock:
        clock.now.return_value = datetime(2026, 11, 18, tzinfo=UTC)
        first = run_inv(runs_root=tmp_path)
        audit = first.run_dir / "audit.jsonl"
        original = audit.read_bytes()
        second = run_inv(runs_root=tmp_path)
    assert first.id != second.id
    assert audit.read_bytes() == original
    assert verify_file(audit).ok
    assert verify_file(second.run_dir / "audit.jsonl").ok


def test_explicit_run_directory_preserves_existing_evidence(tmp_path):
    run_inv(run_dir=tmp_path)
    audit = tmp_path / "audit.jsonl"
    original = audit.read_bytes()
    with pytest.raises(FileExistsError):
        run_inv(run_dir=tmp_path)
    assert audit.read_bytes() == original
    assert verify_file(audit).ok
