# Responsible use

Penumbra is a reference architecture for **defending** an organization. The same building blocks
(behavioral baselines, OSINT, deception) can hurt innocent people if they're deployed carelessly.
Read this before connecting real data.

## What ships, and what deliberately doesn't
* **No scrapers.** The dark-web, paste-site, WHOIS and social-graph feeds in `telemetry/world.py`
  are simulated. Real collection must go through licensed threat-intelligence providers and be
  reviewed by counsel (computer-misuse law, platform terms of service, data-protection law).
* **No autonomous action against a person.** Agents can't execute containment. Actions affecting an
  employee require human approval, and suspension requires two people. Keep it that way.
* **Synthetic people only.** Everyone in Operation Low Tide is fictional.

## Before monitoring employees
* Get legal review for your jurisdictions (e.g., GDPR / works-council consultation in the EU,
  state privacy and labor law in the US) and a documented legitimate purpose.
* Tell employees what is monitored, in your acceptable-use policy.
* Involve HR and Legal *before* containment that affects an individual. The default plan in this
  repo revokes sessions before suspension precisely because account takeover is never ruled out.
* Minimize. Penumbra reads message **metadata** by default; content is read only for external or
  flagged communications, and only through quarantine.

## Deception
* Canaries and honeytokens must contain **no real data** and must not be designed to harm the
  person who triggers them (no "hack-back").
* Record every deployed decoy in the audit trail (Penumbra does) so it can be removed.

## False positives are real people
The scenario includes a decoy (a researcher logging in from a conference abroad) for a reason. Every
dismissal and every finding is recorded with its evidence, so a human can audit why someone was or
wasn't escalated. Keep a human in the loop and keep the record.
