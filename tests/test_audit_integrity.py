from __future__ import annotations

import json

from xdr.audit_integrity import chain_events, verify_audit_log, verify_events


def test_audit_integrity_chain_detects_tampering():
    events = [
        {"ts": "2026-05-07T00:00:00Z", "msg": "LOGIN_OK", "actor": "admin"},
        {"ts": "2026-05-07T00:01:00Z", "msg": "INCIDENT_EXPORT", "actor": "tenant-a"},
    ]
    chained = chain_events(events)

    assert verify_events(chained).valid is True
    tampered = [dict(item) for item in chained]
    tampered[1]["actor"] = "attacker"
    result = verify_events(tampered)
    assert result.valid is False
    assert result.first_broken_record == 2


def test_audit_integrity_file_reader_handles_plain_and_corrupt_logs(tmp_path):
    good = tmp_path / "audit.jsonl"
    good.write_text(json.dumps({"msg": "A"}) + "\n" + json.dumps({"msg": "B"}) + "\n", encoding="utf-8")
    assert verify_audit_log(good).valid is True

    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"msg":"A"}\nnot-json\n', encoding="utf-8")
    assert verify_audit_log(bad).valid is False
