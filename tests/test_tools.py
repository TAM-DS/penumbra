import pytest

from penumbra.guardrails import EXECUTOR_SCOPES, INVESTIGATOR_SCOPES, Scope, ScopeViolation


def test_investigators_cannot_touch_containment(closed_inv):
    reg = closed_inv.ctx.registry
    with pytest.raises(ScopeViolation):
        reg.invoke("revoke_access_key", {"access_key": "AKIAX"}, INVESTIGATOR_SCOPES)
    with pytest.raises(ScopeViolation):
        reg.invoke("query_events", {}, EXECUTOR_SCOPES)


def test_prohibited_tools_have_no_handler_and_no_scope_reaches_them(closed_inv):
    reg = closed_inv.ctx.registry
    for name in ("wipe_endpoint", "disable_logging", "allowlist_domain", "close_investigation"):
        t = reg.get(name)
        assert t.scope is Scope.PROHIBITED and t.handler is None
        with pytest.raises(ScopeViolation):
            reg.invoke(name, {"target": "x"}, frozenset(Scope))


def test_model_never_sees_out_of_scope_tools(closed_inv):
    names = {t["name"] for t in closed_inv.ctx.registry.anthropic_schema(INVESTIGATOR_SCOPES)}
    assert "query_events" in names and "propose_action" in names
    assert not names & {"revoke_access_key", "suspend_user", "wipe_endpoint", "allowlist_domain"}


def test_findings_must_cite_real_evidence(closed_inv):
    out = closed_inv.ctx.registry.invoke(
        "record_finding", {"title": "t", "detail": "d", "confidence": 0.5, "evidence": ["evt-99999"]},
        INVESTIGATOR_SCOPES)
    assert "error" in out


def test_read_content_only_returns_quarantined_envelope(closed_inv):
    out = closed_inv.ctx.registry.invoke("read_content", {"event_id": "evt-00840"}, INVESTIGATOR_SCOPES)
    assert out["verdict"] == "malicious"
    assert out["content"].startswith("<untrusted_content") and "allowlist_domain" not in out["content"]
