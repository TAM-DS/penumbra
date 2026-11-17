# Security policy

Penumbra is a security tool, so bypasses of its guardrails count as vulnerabilities, not just bugs.

**In scope:** any way for agent-controlled or adversary-controlled input to cause a containment
action without the policy gate and the required human approvals; quarantine bypasses that let
hidden instructions reach a model; audit-chain forgery without the signing key.

Please report privately through GitHub Security Advisories ("Report a vulnerability" on the
repository's Security tab) rather than a public issue. Include a reproducing scenario if you can;
a failing test in `tests/` is ideal.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the threats already considered.
