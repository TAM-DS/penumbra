"""Layer 4 — zero-trust guardrails: quarantine, scoped tools, signed audit, policy gate."""
from .audit import AuditLog, verify_file, verify_records
from .policy import ActionRequest, Approval, Decision, PolicyContext, PolicyGate
from .quarantine import Quarantine, QuarantineResult, Verdict
from .tools import EXECUTOR_SCOPES, INVESTIGATOR_SCOPES, Scope, ScopeViolation, Tier, Tool, ToolRegistry

__all__ = ["AuditLog", "verify_file", "verify_records", "ActionRequest", "Approval", "Decision",
           "PolicyContext", "PolicyGate", "Quarantine", "QuarantineResult", "Verdict",
           "EXECUTOR_SCOPES", "INVESTIGATOR_SCOPES", "Scope", "ScopeViolation", "Tier", "Tool",
           "ToolRegistry"]
