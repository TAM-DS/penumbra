"""Layer 2: the knowledge store. Threat TTPs, policies and past incidents.

The demo uses a small lexical retriever with no dependencies, so it runs
offline and returns the same results every time. The ``KnowledgeStore``
interface (``add`` / ``search``) maps directly onto a vector store: back it
with pgvector or Qdrant in production and nothing upstream changes.

After an incident closes, the reporting step calls ``add()`` with the lessons
learned. That's how the system learns from each attack.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class Doc:
    id: str
    title: str
    text: str
    kind: str = "ttp"  # ttp | policy | incident
    tags: list[str] = field(default_factory=list)


SEED_DOCS = [
    Doc("T1078.004", "Valid Accounts: Cloud Accounts",
        "Adversary or insider uses legitimate credentials. Indicators: login from new ASN, "
        "hosting or VPN egress, new device, unusual hour."),
    Doc("T1098.001", "Account Manipulation: Additional Cloud Credentials",
        "Creating new access keys on an existing service account to obtain persistent, "
        "less-attributable access. CreateAccessKey by a human on a pipeline service account."),
    Doc("T1213.003", "Data from Information Repositories: Code Repositories",
        "Cloning sensitive repositories the actor has no history with."),
    Doc("T1530", "Data from Cloud Storage",
        "Bulk GetObject against crown-jewel buckets such as model checkpoints."),
    Doc("T1074.002", "Data Staged: Remote Data Staging",
        "Copying collected data into a staging bucket before exfiltration."),
    Doc("T1537", "Transfer Data to Cloud Account",
        "Bucket policy or ACL granting an external AWS account access. Exfiltration "
        "without traffic leaving the provider."),
    Doc("T1566.002", "Phishing: Spearphishing Link",
        "Targeted email with credential-harvesting link, display text mismatched to href, "
        "look-alike domain, urgent re-enrollment pretext."),
    Doc("T1583.001", "Acquire Infrastructure: Domains",
        "Recently registered look-alike or typosquat domains with privacy proxy."),
    Doc("T1585.001", "Establish Accounts: Social Media Accounts",
        "Synthetic personas with GAN avatars, new profiles, zero posts, connections clustered "
        "at one target organization, recruiter pretext."),
    Doc("AML.T0051", "LLM Prompt Injection",
        "Instructions embedded in data (HTML comments, hidden text, zero-width characters) "
        "to hijack an AI agent that processes that data. Indirect prompt injection."),
    Doc("AML.T0024", "Exfiltration via AI Inference API",
        "High-volume embedding or inference calls used to extract model behavior or "
        "weights. Order-of-magnitude spike over baseline from a new key."),
    Doc("INS-DEPARTING", "Insider risk: departing employee",
        "Data collection spikes in the window between resignation and last day. Combine with "
        "contact from competitors or recruiters.", kind="ttp", tags=["insider"]),
    Doc("POL-001", "Containment policy",
        "Investigation is read-only. Containment requires human approval. Irreversible actions "
        "(wipe, delete, disable logging) are never permitted to agents. Protected principals "
        "(executives, break-glass) require two-person sign-off.", kind="policy"),
]

_tok = re.compile(r"[a-z0-9]+")


def _tokens(s: str) -> list[str]:
    return _tok.findall(s.lower())


class KnowledgeStore:
    def __init__(self, docs: list[Doc] | None = None) -> None:
        self.docs: list[Doc] = []
        self._df: Counter[str] = Counter()
        for d in docs or SEED_DOCS:
            self.add(d)

    def add(self, doc: Doc) -> None:
        self.docs.append(doc)
        self._df.update(set(_tokens(doc.title + " " + doc.text)))

    def get(self, doc_id: str) -> Doc | None:
        return next((d for d in self.docs if d.id == doc_id), None)

    def search(self, query: str, k: int = 3) -> list[dict]:
        q = _tokens(query)
        n = len(self.docs)
        scored = []
        for d in self.docs:
            tf = Counter(_tokens(d.title + " " + d.text))
            s = sum(tf[t] * math.log(1 + n / (1 + self._df[t])) for t in q if t in tf)
            if s > 0:
                scored.append((s, d))
        scored.sort(key=lambda x: -x[0])
        return [{"id": d.id, "title": d.title, "kind": d.kind, "score": round(s, 2),
                 "text": d.text} for s, d in scored[:k]]
