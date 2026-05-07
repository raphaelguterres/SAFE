from __future__ import annotations

import hashlib
import time

from agent.response_executor import EndpointResponseExecutor
from server.response_policy import sign_response_policy


SECRET = "s" * 32


def _signed_action(action_type: str, payload: dict | None = None, *, expires_offset: int = 120) -> dict:
    nonce = "n" * 16
    expires_at = int(time.time()) + expires_offset
    policy = {
        "tenant_id": "tenant-a",
        "host_id": "host-a",
        "action_type": action_type,
        "nonce": nonce,
        "expires_at": expires_at,
        "signature": sign_response_policy(
            SECRET,
            tenant_id="tenant-a",
            host_id="host-a",
            action_type=action_type,
            nonce=nonce,
            expires_at=expires_at,
        ),
    }
    return {"action_type": action_type, "payload": payload or {}, "policy": policy}


def _executor(**overrides):
    params = {
        "host_id": "host-a",
        "tenant_id": "tenant-a",
        "policy_secret": SECRET,
        "dry_run": True,
    }
    params.update(overrides)
    return EndpointResponseExecutor(**params)


def test_executor_refuses_unsigned_action():
    result = _executor().execute({"action_type": "ping", "payload": {}})

    assert result.status == "refused"
    assert result.result["error"] == "missing_policy"


def test_executor_accepts_signed_safe_action_and_audits():
    audits = []
    result = _executor(audit_sink=audits.append).execute(_signed_action("ping"))

    assert result.status == "success"
    assert result.result["message"] == "pong"
    assert result.audit_event["action_type"] == "ping"
    assert audits and audits[0]["status"] == "success"


def test_executor_writes_local_jsonl_audit(tmp_path):
    audit_path = tmp_path / "response_audit.jsonl"
    result = _executor(audit_log_path=audit_path).execute(_signed_action("ping"))

    assert result.status == "success"
    assert audit_path.exists()
    assert '"action_type": "ping"' in audit_path.read_text(encoding="utf-8")


def test_executor_refuses_expired_policy():
    result = _executor().execute(_signed_action("ping", expires_offset=-10))

    assert result.status == "refused"
    assert result.result["error"] == "policy_expired"


def test_executor_redacts_sensitive_diagnostics_provider_fields():
    result = _executor(
        diagnostics_provider=lambda: {"api_key": "secret", "buffer_pending": 2}
    ).execute(_signed_action("collect_diagnostics"))

    assert result.status == "success"
    assert "api_key" not in result.result
    assert result.result["buffer_pending"] == 2


def test_executor_refuses_protected_process_kill():
    result = _executor().execute(
        _signed_action(
            "kill_process_guarded",
            {"pid": 500, "process_name": "lsass.exe", "explicit_approval": True},
        )
    )

    assert result.status == "refused"
    assert result.result["error"] == "protected_process"


def test_executor_quarantines_without_deleting_evidence_permanently(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"netguard suspicious sample")
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    quarantine_dir = tmp_path / "quarantine"
    executor = _executor(dry_run=False, quarantine_dir=quarantine_dir)

    result = executor.execute(
        _signed_action(
            "quarantine_file_guarded",
            {
                "path": str(sample),
                "sha256": digest,
                "signature_checked": True,
            },
        )
    )

    assert result.status == "success"
    assert result.result["deleted"] is False
    assert not sample.exists()
    assert quarantine_dir.exists()


def test_executor_refuses_quarantine_path_traversal(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"netguard suspicious sample")
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()

    result = _executor(quarantine_roots=[tmp_path]).execute(
        _signed_action(
            "quarantine_file_guarded",
            {
                "path": str(tmp_path / ".." / sample.name),
                "sha256": digest,
                "signature_checked": True,
            },
        )
    )

    assert result.status == "refused"
    assert result.result["error"] == "path_traversal_refused"


def test_executor_refuses_quarantine_outside_scope_without_explicit_approval(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"netguard suspicious sample")
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()

    result = _executor(quarantine_roots=[tmp_path / "allowed"]).execute(
        _signed_action(
            "quarantine_file_guarded",
            {
                "path": str(sample),
                "sha256": digest,
                "signature_checked": True,
            },
        )
    )

    assert result.status == "refused"
    assert result.result["error"] == "quarantine_scope_requires_explicit_approval"


def test_executor_firewall_rollback_is_dry_run_and_netguard_scoped():
    ok = _executor().execute(_signed_action("rollback_firewall_rule", {"ip": "8.8.8.8"}))
    refused = _executor().execute(_signed_action("rollback_firewall_rule", {"rule_name": "Other Vendor Rule"}))

    assert ok.status == "skipped"
    assert ok.result["rule_name"] == "NetGuard Block 8.8.8.8"
    assert refused.status == "refused"


def test_executor_safe_host_isolation_requires_netguard_server_allowlist():
    result = _executor().execute(_signed_action("safe_host_isolation", {"allowed_ips": ["127.0.0.1"]}))

    assert result.status == "refused"
    assert result.result["error"] == "netguard_server_ip_required"


def test_executor_safe_host_isolation_dry_run_has_rollback_plan():
    result = _executor().execute(
        _signed_action(
            "safe_host_isolation",
            {"server_ip": "10.0.0.10", "dns_ips": ["10.0.0.53"]},
        )
    )

    assert result.status == "skipped"
    assert result.result["rollback_action"] == "rollback_host_isolation"
    assert "10.0.0.10" in result.result["allowed_ips"]


def test_executor_rollback_host_isolation_is_netguard_scoped():
    result = _executor().execute(
        _signed_action(
            "rollback_host_isolation",
            {"rule_names": ["NetGuard Isolation Allow 10.0.0.10", "Other Rule"]},
        )
    )

    assert result.status == "skipped"
    assert result.result["rule_names"] == ["NetGuard Isolation Allow 10.0.0.10"]
