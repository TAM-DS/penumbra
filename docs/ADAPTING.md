# Adapting Penumbra to your environment

Penumbra is meant to be cloned and adapted, the way a forward-deployed engineer adapts a reference
architecture to each customer's threat surface. Here is the order to do it in.

## 1. Replace the senses (Layer 1)
Write a normalizer per source that yields `penumbra.events.Event`:

| Source | `source` | Typical `kind`s | Put free text in `content`? |
|---|---|---|---|
| Okta System Log / Entra sign-ins | `okta` | `login` (attrs: `asn`, `city`, `device_id`, `new_device`, `mfa`) | no |
| CloudTrail / CloudTrail Lake | `cloudtrail` | `GetObject`, `PutObject`, `CreateAccessKey`, `PutBucketPolicy` | no |
| GitHub audit log stream | `github` | `repo_clone`, `push` | no |
| Slack / Teams audit + Connect | `slack` | `message` (attrs: `external`) | only external or flagged |
| Mail gateway | `email` | `inbound_email` | yes, it will be quarantined |
| LLM gateway | `model_gateway` | `embedding_calls`, `completion_calls` | prompts: yes |
| Threat-intel provider | `osint` | `persona_contact`, `paste_hit`, `domain_registered` | yes |

Publish them to `RedisStreamBus` (or your Kafka topic) and pass them to `Investigation`.

## 2. Replace the world model
`telemetry/world.py` holds the directory, sensitive assets, service-account dependencies, HR
context, change tickets, authorized approvers and the OSINT lookups. Each one maps to a system you
already have: IdP, CMDB, HRIS, ITSM, and a TI provider.

## 3. Persist memory (Layer 2)
* `Neo4jGraph(uri, user, password)` instead of `TemporalGraph()`.
* Back `KnowledgeStore` with pgvector or Qdrant; seed it with your own post-mortems.

## 4. Choose the reasoning backend (Layer 3)
* `ANTHROPIC_API_KEY` set → Claude. Tune models with `PENUMBRA_MODEL_FAST`, `PENUMBRA_MODEL`,
  `PENUMBRA_MODEL_DEEP`.
* Add an agent by subclassing `Agent`: set `SYSTEM` and `task()` for LLM mode and optionally
  `analyze()` for deterministic mode. Give it the narrowest `scopes` that work.

## 5. Encode your policy (Layer 4)
* Edit thresholds and protected principals in `guardrails/policy.py`, or
* run OPA with `policies/penumbra.rego`, set `PENUMBRA_OPA_URL`, and use `OPAPolicyGate`.
  Both evaluate, and either can deny.
* Provide `PENUMBRA_AUDIT_KEY` (Ed25519 seed, hex) from your KMS and ship `audit.jsonl` to WORM
  storage.

## 6. Wire containment to real systems (Layer 5)
Replace the `CONTAIN` handlers in `agents/toolkit.py` (`revoke_access_key`, `force_mfa_reauth`, …)
with calls to AWS IAM, Okta, your mail gateway and so on. Keep them in a **separate service with its
own credentials**: the investigators must never hold them. Put SSO in front of the approval API so
approver identity is real.

## 7. Prove it holds
Keep `tests/test_investigation.py::test_red_team_hijack_is_contained_by_code_not_by_the_model`
green, and add a red-team scenario for your own environment.
