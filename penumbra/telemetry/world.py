"""The simulated organization Penumbra defends.

Everything here is fictional. "Halcyon Dynamics" is an invented frontier-model
startup; every person, domain, ASN mapping and account ID is synthetic. The
external intelligence (WHOIS, persona profiles, paste-site hits) is a
*simulated* OSINT feed. Penumbra ships no scrapers. See docs/RESPONSIBLE_USE.md.

To adapt Penumbra to your own environment, replace this module with
connectors to your directory, CMDB and threat-intel providers. The agents
only depend on the lookup functions at the bottom of this file.
"""

from __future__ import annotations

from dataclasses import dataclass

CORP_DOMAIN = "halcyondyn.com"
CORP_DOMAINS = {CORP_DOMAIN, "halcyondynamics.com"}
CORP_AWS_ACCOUNT = "220917344105"


@dataclass(frozen=True)
class Employee:
    user: str
    name: str
    title: str
    home_asn: str
    home_city: str
    repos: tuple[str, ...]
    protected: bool = False  # executives / break-glass: never auto-actioned
    iam_admin: bool = False


EMPLOYEES: dict[str, Employee] = {
    e.user: e
    for e in [
        Employee("dana.reyes", "Dana Reyes", "Senior ML Engineer", "AS7922", "Austin",
                 ("halcyon/eval-harness", "halcyon/data-loaders")),
        Employee("priya.natarajan", "Priya Natarajan", "IT Administrator", "AS7018", "Austin",
                 ("halcyon/it-automation",), iam_admin=True),
        Employee("ruth.kim", "Ruth Kim", "Research Scientist", "AS7922", "Austin",
                 ("halcyon/eval-harness", "halcyon/research-notebooks")),
        Employee("jon.alvarez", "Jon Alvarez", "ML Infra Lead", "AS20115", "Austin",
                 ("halcyon/frontier-ckpt-tools", "halcyon/model-weights-registry",
                  "halcyon/infra"), iam_admin=True),
        Employee("sam.okafor", "Sam Okafor", "Software Engineer", "AS7922", "Austin",
                 ("halcyon/web", "halcyon/api")),
        Employee("lena.fischer", "Lena Fischer", "Security Engineer", "AS7018", "Austin",
                 ("halcyon/infra", "halcyon/detections")),
        Employee("marcus.chen", "Marcus Chen", "CFO", "AS7018", "Austin", (), protected=True),
        Employee("evelyn.hart", "Evelyn Hart", "CEO", "AS7018", "Austin", (), protected=True),
    ]
}

# ASN reputation. AS9009 (M247) is commodity VPN / hosting egress.
ASN_INFO = {
    "AS7922": {"org": "Comcast", "type": "residential", "city": "Austin"},
    "AS7018": {"org": "AT&T", "type": "residential", "city": "Austin"},
    "AS20115": {"org": "Charter", "type": "residential", "city": "Austin"},
    "AS3320": {"org": "Deutsche Telekom", "type": "residential", "city": "Berlin"},
    "AS9009": {"org": "M247 Ltd", "type": "hosting/vpn", "city": "Bucharest"},
}

# Crown-jewel data. Sensitivity drives triage scoring.
SENSITIVE_PREFIXES = {
    "s3://halcyon-ml-artifacts/checkpoints/": "crown_jewel",
    "s3://halcyon-ml-artifacts/eval/": "internal",
    "s3://halcyon-scratch-": "scratch",
}
SENSITIVE_REPOS = {"halcyon/frontier-ckpt-tools", "halcyon/model-weights-registry"}

# Service accounts → what depends on them (feeds the counterfactual simulator).
SERVICE_ACCOUNTS = {
    "svc-ml-batch": {
        "owner": "jon.alvarez",
        "pipelines": ["nightly-eval", "checkpoint-sync", "embedding-refresh"],
        "baseline_daily_embedding_calls": 2000,
    },
}

USER_DEPENDENCIES = {
    "dana.reyes": {"repos_owned": 14, "oncall_rotations": ["ml-platform-secondary"],
                   "scheduled_jobs": ["weekly-eval-report"]},
}

# HR context (synthetic). Departing-employee status is a classic insider-risk
# signal; travel records suppress false positives on geo anomalies.
HR_RECORDS = {
    "dana.reyes": {"status": "resignation_submitted", "since": "2026-11-08",
                   "last_day": "2026-11-21", "travel": []},
    "ruth.kim": {"status": "active", "travel": [{"city": "Berlin", "from": "2026-11-11",
                                                  "to": "2026-11-15", "purpose": "NeurIPS workshop"}]},
}

# Approved change tickets (synthetic ITSM feed). Used to check whether an
# unusual admin action was sanctioned.
CHANGE_TICKETS = [
    {"id": "CHG-4471", "date": "2026-10-14", "requester": "jon.alvarez",
     "summary": "Rotate svc-ml-batch access key", "target": "svc-ml-batch"},
]

# People allowed to approve containment (fictional). Role must match.
AUTHORIZED_APPROVERS = {
    "lena.fischer": "security",
    "alex.morgan": "security",   # CISO
    "ir-oncall": "security",
}

# ------------------------------------------------------------------ simulated OSINT
# A real deployment wires these lookups to licensed threat-intel providers.
WHOIS = {
    "halcyondyn.co": {"registered": "2026-11-09", "registrar": "NameSilo",
                      "privacy_proxy": True, "mx": "mx.privateemail.com",
                      "hosting_asn": "AS9009"},
    "halcyondyn-talent.com": {"registered": "2026-10-19", "registrar": "NameSilo",
                              "privacy_proxy": True, "mx": "mx.privateemail.com",
                              "hosting_asn": "AS9009"},
    "halcyondyn.com": {"registered": "2021-03-02", "registrar": "MarkMonitor",
                       "privacy_proxy": False, "mx": "aspmx.l.google.com",
                       "hosting_asn": "AS15169"},
}

PERSONAS = {
    "julian.voss@halcyondyn-talent.com": {
        "display_name": "Julian Voss",
        "claimed_role": "Principal Talent Partner",
        "profile_created": "2026-10-21",
        "posts": 0,
        "avatar_gan_score": 0.94,  # output of a synthetic-face classifier
        "connections_total": 31,
        "connections_at_target_org": ["dana.reyes", "priya.natarajan", "ruth.kim", "marcus.chen"],
        "reused_avatar_hits": 2,
    }
}

THREAT_FEED = {
    "AS9009": {"tags": ["vpn-egress", "seen-in-espionage-campaigns"], "confidence": 0.6},
    "491882034417": {"tags": ["external-aws-account", "linked-to-exfil-staging"], "confidence": 0.7},
}


def lookup_whois(domain: str) -> dict:
    return WHOIS.get(domain.lower(), {"error": "no record"})


def lookup_persona(handle: str) -> dict:
    return PERSONAS.get(handle.lower(), {"error": "no profile"})


def lookup_threat_intel(indicator: str) -> dict:
    return THREAT_FEED.get(indicator, {"tags": [], "confidence": 0.0})
