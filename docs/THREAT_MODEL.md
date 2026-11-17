# Threat model: attacks on Penumbra itself

A counterintelligence agent is itself a high-value target. Its job is to read adversary-written
content, and it sits close to powerful containment levers. This document lists what we defend
against, how, and what is out of scope.

## Assets
1. Containment levers (key revocation, suspension, blocking).
2. Investigation integrity: findings, hypothesis, the record of who approved what.
3. Investigation confidentiality: who is under suspicion.
4. Availability of the defender (not being tricked into closing cases or into DoS-ing production).

## Adversary capabilities assumed
* Controls the content of emails, chat messages, web pages, paste dumps and persona profiles
  that Penumbra reads.
* May know Penumbra is deployed and how it works (it's open source).
* May be an insider with legitimate credentials.
* May fully compromise the reasoning of one LLM agent (we assume the model *can* be hijacked).

## Threats and mitigations

| # | Threat | Mitigation | Verified by |
|---|---|---|---|
| T1 | **Indirect prompt injection** makes an agent take attacker-chosen actions | Quarantine strips and spotlights the text; investigators have no containment scope; prohibited tools have no handler; policy gate P-002/P-003 | `test_red_team_hijack_is_contained_by_code_not_by_the_model`, `test_claude_loop_uses_scoped_tools_and_quarantine` |
| T2 | Injection makes the defender **close the investigation / allowlist attacker infra** | `close_investigation`, `allowlist_domain` are prohibited and defense-weakening, so they're human-only | `test_policy.py::test_prohibited_tools_are_always_denied` |
| T3 | Adversary content used as the *justification* for harming a victim (e.g. a forged email framing an employee) | Taint ledger + P-005: no action rests solely on tainted events; P-006 needs ≥2 independent sources | `test_action_resting_only_on_tainted_content_is_denied` |
| T4 | Hidden-channel smuggling (HTML comments, CSS-hidden text, zero-width, Unicode tags, base64) | Channel-specific stripping before any model call | `test_quarantine.py` |
| T5 | Model hallucinates evidence | `record_finding` rejects unknown event IDs; every edge carries evidence IDs | `test_findings_must_cite_real_evidence` |
| T6 | Overreach / production outage from containment | Blast-radius simulator; narrow-first plans; tiers; rate limit P-009 | `test_containment_plan_is_surgical_and_tiered` |
| T7 | Single rogue or coerced approver | DUAL tier requires two distinct authorized approvers; the proposer can't approve | `test_execution_requires_distinct_authorized_approvers` |
| T8 | Time-of-check/time-of-use: a request changes or context shifts between approval and execution | Gate re-evaluated at execution with approvals attached | `ApprovalQueue._execute` |
| T9 | Audit tampering to hide misuse | Hash chain + Ed25519 signatures; public key published separately | `test_audit.py` (edit, delete, re-hash without key) |
| T10 | "Why did the AI do that?" is unanswerable | Prompt-state hash + model ID on every tool call | `test_prompt_state_is_hashed_not_stored` |
| T11 | Supply-chain injection via front-end CDNs | Vendored JS; no runtime third-party script loads | `penumbra/ui/vendor/` |
| T12 | Trojan-Source / invisible characters in the code base | Zero-width and bidi characters only appear as escapes in source; a lint rule (PLE2502/2515) is enabled | `ruff` in CI |

## Residual risks and out of scope
* **Rule-based injection detection is not complete.** Novel phrasings will get through. That's
  exactly why the scope guard and policy gate don't depend on detection. A classifier layer is on
  the roadmap.
* **Data poisoning of telemetry** (an insider generating cover traffic for weeks) can shift
  baselines. Mitigation would be long-horizon baselines and peer-group comparison.
* **Confidentiality of investigations** depends on deployment access control, which is not
  implemented in this reference server (it binds to localhost by default).
* **Key management.** The audit signing key is per-run or comes from `PENUMBRA_AUDIT_KEY`. Production
  should use an HSM/KMS and ship records to WORM storage.
* The demo server has **no authentication**; approver identity is selected in the UI. Production
  must bind approvals to SSO identity.
