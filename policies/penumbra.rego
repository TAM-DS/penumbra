# Open Policy Agent mirror of Penumbra's deterministic policy gate.
#
#   opa run --server policies/penumbra.rego
#   export PENUMBRA_OPA_URL=http://localhost:8181   # used by OPAPolicyGate
#
# Input: {"request": ActionRequest, "at_execution": bool, "tainted": [event ids]}
# Both OPA and the built-in gate evaluate every request; either can deny.
package penumbra

import rego.v1

prohibited := {"wipe_endpoint", "delete_data", "disable_logging", "delete_audit_log",
	"allowlist_domain", "close_investigation"}

defense_weakening := {"allowlist_domain", "close_investigation", "disable_logging",
	"unblock_ip", "delete_audit_log", "suppress_alert"}

containment := {"revoke_access_key", "remove_bucket_policy", "force_mfa_reauth",
	"block_domain", "deploy_canary", "suspend_user", "isolate_endpoint"}

protected_principals := {"evelyn.hart", "marcus.chen"}

default allow := false

deny contains "P-002: prohibited / irreversible action" if input.request.tool in prohibited

deny contains "P-003: defense-weakening action is human-only" if input.request.tool in defense_weakening

deny contains "P-004: not a containment tool" if {
	not input.request.tool in containment
	not input.request.tool in prohibited
}

deny contains "P-005: evidence is entirely tainted by prompt injection" if {
	count(input.request.evidence) > 0
	every e in input.request.evidence { e in input.tainted }
}

deny contains "P-007: confidence below 0.7" if input.request.confidence < 0.7

tier := "DUAL" if {
	input.request.target_principal in protected_principals
} else := "DUAL" if {
	input.request.tool in {"suspend_user", "isolate_endpoint"}
} else := "SINGLE"

allow if count(deny) == 0

decision := {"allow": allow, "deny": deny, "tier": tier}
