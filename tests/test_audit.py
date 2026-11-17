import copy
import json

from penumbra.guardrails import AuditLog, verify_file, verify_records


def make(path=None):
    a = AuditLog(path)
    for i in range(5):
        a.append("forensics", "tool_call", {"tool": "query_events", "i": i}, model="m",
                 prompt_state={"ctx": i})
    return a


def test_chain_verifies():
    v = make().verify()
    assert v.ok and v.records == 5


def test_edit_is_detected():
    a = make()
    recs = copy.deepcopy(a.records)
    recs[2]["payload"]["tool"] = "revoke_access_key"
    v = verify_records(recs, a.public_key_hex)
    assert not v.ok and v.first_bad_seq == 2 and "altered" in v.reason


def test_deletion_is_detected():
    a = make()
    recs = copy.deepcopy(a.records)
    del recs[1]
    assert not verify_records(recs, a.public_key_hex).ok


def test_rehash_without_key_is_detected():
    """An attacker who edits a record AND recomputes hashes still can't forge signatures."""
    from penumbra.guardrails.audit import GENESIS, sha256_json
    a = make()
    recs = copy.deepcopy(a.records)
    recs[3]["payload"]["i"] = 999
    prev = recs[2]["hash"]
    for r in recs[3:]:
        r["prev_hash"] = prev
        r["hash"] = sha256_json({k: v for k, v in r.items() if k not in ("hash", "sig")})
        prev = r["hash"]
    v = verify_records(recs, a.public_key_hex)
    assert not v.ok and v.reason == "invalid signature"
    assert GENESIS == "0" * 64


def test_prompt_state_is_hashed_not_stored():
    rec = make().records[0]
    assert len(rec["prompt_state_sha256"]) == 64 and "ctx" not in json.dumps(rec)


def test_file_roundtrip(tmp_path):
    p = tmp_path / "audit.jsonl"
    make(p)
    assert verify_file(p).ok
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["actor"] = "nobody"
    lines[1] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")
    assert not verify_file(p).ok


def test_demo_cli_writes_verifiable_signed_log(tmp_path):
    from penumbra.cli import main

    assert main(["demo", "--auto-approve", "--out", str(tmp_path)]) == 0
    (log,) = tmp_path.glob("*/audit.jsonl")
    assert main(["verify-audit", str(log)]) == 0
    assert (log.parent / "report.md").exists()
