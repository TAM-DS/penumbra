"""Layer 4b: scoped, least-privilege tools.

The model can propose; the system decides what is authorized.

Every capability in Penumbra is a ``Tool`` with a **scope**:

* ``READ``: query telemetry, the graph, the knowledge store, OSINT lookups.
* ``NOTE``: append findings to the shared scratchpad.
* ``PROPOSE``: file an action request. It doesn't *do* anything; it puts a
  card in the approval queue.
* ``CONTAIN``: revoke keys, force MFA, deploy canaries, block domains. Only
  the separate **executor service** holds this scope, and it only acts on
  requests that cleared the policy gate *and* human approval.
* ``PROHIBITED``: irreversible or defense-weakening operations (wipe a
  host, disable logging, allowlist a domain, close an investigation). They
  are registered by name so they can be refused by name, and they have no
  handler, so no code path can ever run them.

Investigation agents are constructed with READ, NOTE and PROPOSE only. A
hijacked investigator therefore has no tool that changes the world.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any


class Scope(str, Enum):
    READ = "read"
    NOTE = "note"
    PROPOSE = "propose"
    CONTAIN = "contain"
    PROHIBITED = "prohibited"


class Tier(IntEnum):
    AUTO = 0      # routine enrichment: runs without a human
    SINGLE = 1    # medium-risk containment: one-click approval
    DUAL = 2      # high-risk: two distinct approvers
    BLOCKED = 3   # never executable


INVESTIGATOR_SCOPES = frozenset({Scope.READ, Scope.NOTE, Scope.PROPOSE})
EXECUTOR_SCOPES = frozenset({Scope.CONTAIN})

_PYTYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool,
            "array": list, "object": dict}


class ScopeViolation(PermissionError):
    pass


class SchemaViolation(ValueError):
    pass


@dataclass
class Tool:
    name: str
    description: str
    scope: Scope
    params: dict[str, dict[str, Any]] = field(default_factory=dict)  # name -> JSON schema
    required: tuple[str, ...] = ()
    handler: Callable[..., Any] | None = None
    tier: Tier = Tier.AUTO
    irreversible: bool = False

    def input_schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": self.params, "required": list(self.required),
                "additionalProperties": False}

    def validate(self, args: dict[str, Any]) -> None:
        for r in self.required:
            if r not in args:
                raise SchemaViolation(f"{self.name}: missing required argument '{r}'")
        for k, v in args.items():
            if k not in self.params:
                raise SchemaViolation(f"{self.name}: unexpected argument '{k}'")
            t = _PYTYPES.get(self.params[k].get("type", "string"))
            if t and not isinstance(v, t):
                raise SchemaViolation(f"{self.name}: '{k}' must be {self.params[k]['type']}")
            enum = self.params[k].get("enum")
            if enum and v not in enum:
                raise SchemaViolation(f"{self.name}: '{k}' must be one of {enum}")


class ToolRegistry:
    def __init__(self) -> None:
        self.tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> Tool:
        if tool.scope is Scope.PROHIBITED:
            tool.handler = None
            tool.tier = Tier.BLOCKED
        self.tools[tool.name] = tool
        return tool

    def get(self, name: str) -> Tool | None:
        return self.tools.get(name)

    def for_scopes(self, scopes: frozenset[Scope]) -> list[Tool]:
        return [t for t in self.tools.values() if t.scope in scopes]

    def anthropic_schema(self, scopes: frozenset[Scope]) -> list[dict[str, Any]]:
        """Tool definitions for the Claude Messages API, filtered by scope.

        Out-of-scope tools aren't merely refused: the model is never told
        they exist.
        """
        return [{"name": t.name, "description": t.description, "input_schema": t.input_schema()}
                for t in self.for_scopes(scopes)]

    def invoke(self, name: str, args: dict[str, Any], scopes: frozenset[Scope],
               caller: str | None = None) -> Any:
        tool = self.tools.get(name)
        if tool is None:
            raise ScopeViolation(f"unknown tool '{name}'")
        if tool.scope not in scopes:
            raise ScopeViolation(f"tool '{name}' requires scope '{tool.scope.value}'; "
                                 f"caller holds {sorted(s.value for s in scopes)}")
        if tool.handler is None:
            raise ScopeViolation(f"tool '{name}' is prohibited and has no handler")
        tool.validate(args)
        if caller is not None and "_agent" in inspect.signature(tool.handler).parameters:
            return tool.handler(**args, _agent=caller)
        return tool.handler(**args)
