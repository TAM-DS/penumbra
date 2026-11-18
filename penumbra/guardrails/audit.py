"""Layer 4c: cryptographically signed, hash-chained audit trail.

Every tool call, quarantine verdict, policy decision, approval and execution
is appended here with:

* ``prompt_state_sha256``: a hash of the exact context the agent held when
  it decided (so "why did the AI do that?" has a verifiable answer),
* ``model``: the model or analytic engine that produced the decision,
* ``prev_hash`` / ``hash``: a SHA-256 chain, so deleting or editing any
  record breaks every record after it,
* ``sig``: an Ed25519 signature over the hash. Verifiers need only the
  public key, which is published next to the log.

``verify()`` re-derives the chain and checks every signature.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

GENESIS = "0" * 64


def sha256_json(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    records: int
    first_bad_seq: int | None = None
    reason: str = ""


class AuditLog:
    def __init__(self, path: Path | None = None, key: Ed25519PrivateKey | None = None) -> None:
        seed = os.environ.get("PENUMBRA_AUDIT_KEY")
        if key is None and seed:
            key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
        self._key = key or Ed25519PrivateKey.generate()
        self.records: list[dict[str, Any]] = []
        self.path = path
        self._lock = threading.Lock()
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(exist_ok=False)
            (path.parent / "audit.pub").write_text(self.public_key_hex)

    @property
    def public_key_hex(self) -> str:
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def append(self, actor: str, kind: str, payload: dict[str, Any], *,
               model: str | None = None, prompt_state: Any = None) -> dict[str, Any]:
        with self._lock:
            prev = self.records[-1]["hash"] if self.records else GENESIS
            body = {
                "seq": len(self.records),
                "ts": datetime.now(UTC).isoformat(),
                "actor": actor,
                "kind": kind,
                "payload": payload,
                "model": model,
                "prompt_state_sha256": sha256_json(prompt_state) if prompt_state is not None else None,
                "prev_hash": prev,
            }
            h = sha256_json(body)
            rec = {**body, "hash": h, "sig": self._key.sign(bytes.fromhex(h)).hex()}
            self.records.append(rec)
            if self.path:
                with self.path.open("a") as f:
                    f.write(json.dumps(rec, default=str) + "\n")
            return rec

    def verify(self) -> VerifyResult:
        return verify_records(self.records, self.public_key_hex)


def verify_records(records: list[dict[str, Any]], public_key_hex: str) -> VerifyResult:
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    prev = GENESIS
    for i, rec in enumerate(records):
        body = {k: v for k, v in rec.items() if k not in ("hash", "sig")}
        if rec.get("seq") != i:
            return VerifyResult(False, len(records), i, "sequence gap (record removed or reordered)")
        if body.get("prev_hash") != prev:
            return VerifyResult(False, len(records), i, "broken chain link")
        if sha256_json(body) != rec.get("hash"):
            return VerifyResult(False, len(records), i, "record contents altered")
        try:
            pub.verify(bytes.fromhex(rec["sig"]), bytes.fromhex(rec["hash"]))
        except Exception:
            return VerifyResult(False, len(records), i, "invalid signature")
        prev = rec["hash"]
    return VerifyResult(True, len(records))


def verify_file(path: Path) -> VerifyResult:
    pub = (path.parent / "audit.pub").read_text().strip()
    recs = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return verify_records(recs, pub)
