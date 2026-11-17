"""Exercise the Claude tool-use loop with a fake client (no network, no key)."""
import asyncio
import copy
import sys
import types

from penumbra.agents.osint import OsintAgent
from penumbra.engine import Investigation


class Block:
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def model_dump(self, exclude_none=False):
        return dict(self.__dict__)


class Resp:
    def __init__(self, content, stop):
        self.content, self.stop_reason = content, stop


class FakeMessages:
    def __init__(self, log):
        self.log, self.turn = log, 0

    async def create(self, **kw):
        self.log.append(copy.deepcopy(kw))
        self.turn += 1
        if self.turn == 1:
            return Resp([Block(type="text", text="Reading the suspicious email through quarantine."),
                         Block(type="tool_use", id="t1", name="read_content", input={"event_id": "evt-00840"})],
                        "tool_use")
        if self.turn == 2:
            # A (hypothetically) hijacked model tries the attacker's instruction.
            return Resp([Block(type="tool_use", id="t2", name="allowlist_domain",
                               input={"target": "halcyondyn.co"})], "tool_use")
        return Resp([Block(type="text", text="Done.")], "end_turn")


def test_claude_loop_uses_scoped_tools_and_quarantine(monkeypatch):
    log = []
    fake = types.ModuleType("anthropic")
    fake.AsyncAnthropic = lambda: types.SimpleNamespace(messages=FakeMessages(log))
    monkeypatch.setitem(sys.modules, "anthropic", fake)

    inv = Investigation(backend="claude")
    asyncio.run(OsintAgent(inv.ctx).run())

    tools_offered = {t["name"] for t in log[0]["tools"]}
    assert "allowlist_domain" not in tools_offered and "revoke_access_key" not in tools_offered
    # the model received only the quarantined envelope
    tool_result = log[1]["messages"][-1]["content"][0]["content"]
    assert "untrusted_content" in tool_result and "SYSTEM OVERRIDE" not in tool_result
    # the hijack attempt was refused by the scope guard and audited
    blocked = [r for r in inv.ctx.audit.records if r["kind"] == "tool_blocked"]
    assert blocked and blocked[0]["payload"]["tool"] == "allowlist_domain"
    assert log[2]["messages"][-1]["content"][0]["is_error"] is True
    # model id is recorded on the audit trail
    assert any(r["model"] and r["model"].startswith("claude-") for r in inv.ctx.audit.records)
