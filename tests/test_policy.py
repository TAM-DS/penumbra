import pytest

from penumbra.guardrails import (
    ActionRequest,
    Approval,
    PolicyContext,
    PolicyGate,
    Scope,
    Tier,
    Tool,
    ToolRegistry,
)

SRC = {"e-okta": "okta", "e-ct": "cloudtrail", "e-mail": "email", "e-mail2": "email"}
TAINTED = {"e-mail", "e-mail2"}


@pytest.fixture
def gate():
    reg = ToolRegistry()
    reg.register(Tool("revoke_access_key", "", Scope.CONTAIN, {"access_key": {"type": "string"}},
                      ("access_key",), handler=lambda access_key: 1, tier=Tier.SINGLE))
    reg.register(Tool("suspend_user", "", Scope.CONTAIN, {"user": {"type": "string"}}, ("user",),
                      handler=lambda user: 1, tier=Tier.DUAL))
    reg.register(Tool("force_mfa_reauth", "", Scope.CONTAIN, {"user": {"type": "string"}}, ("user",),
                      handler=lambda user: 1, tier=Tier.SINGLE))
    reg.register(Tool("query_events", "", Scope.READ, handler=lambda: []))
    for n in ("wipe_endpoint", "allowlist_domain", "close_investigation"):
        reg.register(Tool(n, "", Scope.PROHIBITED, {"target": {"type": "string"}}, irreversible=True))
    return PolicyGate(PolicyContext(reg, lambda e: e in TAINTED, SRC.get, {"evelyn.hart"},
                                    {"lena": "security", "alex": "security"}))


def req(tool, args, ev=("e-okta", "e-ct"), conf=0.9, target=None):
    return ActionRequest(tool, args, "lead", "why", list(ev), conf, target)


def test_well_supported_containment_is_allowed_single(gate):
    d = gate.evaluate(req("revoke_access_key", {"access_key": "AK"}))
    assert d.allowed and d.tier is Tier.SINGLE


@pytest.mark.parametrize("tool", ["wipe_endpoint", "allowlist_domain", "close_investigation"])
def test_prohibited_tools_are_always_denied(gate, tool):
    d = gate.evaluate(req(tool, {"target": "x"}, conf=0.99))
    assert not d.allowed and "P-002" in d.rules


def test_defense_weakening_cites_P003(gate):
    d = gate.evaluate(req("allowlist_domain", {"target": "evil.co"}))
    assert "P-003" in d.rules


def test_unknown_tool_denied(gate):
    assert gate.evaluate(req("format_c_drive", {})).rules == ["P-001"]


def test_action_resting_only_on_tainted_content_is_denied(gate):
    d = gate.evaluate(req("force_mfa_reauth", {"user": "u"}, ev=("e-mail", "e-mail2")))
    assert not d.allowed and "P-005" in d.rules


def test_tainted_event_metadata_still_corroborates(gate):
    d = gate.evaluate(req("force_mfa_reauth", {"user": "u"}, ev=("e-mail", "e-okta")))
    assert d.allowed


def test_single_source_is_insufficient(gate):
    d = gate.evaluate(req("revoke_access_key", {"access_key": "AK"}, ev=("e-okta",)))
    assert not d.allowed and "P-006" in d.rules


def test_low_confidence_denied(gate):
    d = gate.evaluate(req("revoke_access_key", {"access_key": "AK"}, conf=0.5))
    assert "P-007" in d.rules


def test_schema_enforced(gate):
    d = gate.evaluate(req("revoke_access_key", {"access_key": "AK", "rm_rf": True}))
    assert "P-008" in d.rules


def test_read_tools_are_not_containment(gate):
    assert "P-004" in gate.evaluate(req("query_events", {})).rules


def test_protected_principal_escalates_to_dual(gate):
    d = gate.evaluate(req("force_mfa_reauth", {"user": "evelyn.hart"}, target="evelyn.hart"))
    assert d.allowed and d.tier is Tier.DUAL and "T-001" in d.rules


def test_execution_requires_distinct_authorized_approvers(gate):
    r = req("suspend_user", {"user": "u"})
    assert not gate.evaluate(r, [Approval("lena", "security")], at_execution=True).allowed
    assert not gate.evaluate(r, [Approval("lena", "security"), Approval("lena", "security")],
                             at_execution=True).allowed
    d = gate.evaluate(r, [Approval("lena", "security"), Approval("mallory", "security")], at_execution=True)
    assert not d.allowed and "E-001" in d.rules
    assert gate.evaluate(r, [Approval("lena", "security"), Approval("alex", "security")],
                         at_execution=True).allowed


def test_proposer_cannot_approve_own_action(gate):
    r = req("revoke_access_key", {"access_key": "AK"})
    r.proposed_by = "lena"
    assert not gate.evaluate(r, [Approval("lena", "security")], at_execution=True).allowed
