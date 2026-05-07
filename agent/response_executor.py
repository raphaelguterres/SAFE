"""Defensive endpoint response executor for NetGuard agents.

This module intentionally implements guarded, auditable defensive actions only.
It is not a remote shell and it never deletes evidence permanently.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform
import shutil
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from server.response_policy import verify_response_policy


PROTECTED_PROCESSES = {
    "system",
    "wininit",
    "csrss",
    "lsass",
    "services",
    "explorer",
}

CRITICAL_PROCESSES = {"system", "wininit", "csrss", "lsass", "services"}
SUPPORTED_ACTIONS = {
    "collect_diagnostics",
    "flush_buffer",
    "ping",
    "isolate_host_simulated",
    "safe_host_isolation",
    "rollback_host_isolation",
    "block_ip_windows_firewall",
    "rollback_firewall_rule",
    "kill_process_guarded",
    "quarantine_file_guarded",
}


@dataclass(slots=True)
class EndpointResponseResult:
    status: str
    action_type: str
    result: dict[str, Any] = field(default_factory=dict)
    audit_event: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EndpointResponseExecutor:
    """Executes policy-signed defensive response actions on an endpoint."""

    def __init__(
        self,
        *,
        host_id: str,
        tenant_id: str,
        policy_secret: str,
        dry_run: bool = True,
        diagnostics_provider: Callable[[], dict[str, Any]] | None = None,
        buffer_flusher: Callable[[], Any] | None = None,
        audit_sink: Callable[[dict[str, Any]], None] | None = None,
        quarantine_dir: str | Path | None = None,
        audit_log_path: str | Path | None = None,
        quarantine_roots: list[str | Path] | None = None,
    ):
        self.host_id = str(host_id or "").strip()
        self.tenant_id = str(tenant_id or "").strip()
        self.policy_secret = str(policy_secret or "")
        self.dry_run = bool(dry_run)
        self.diagnostics_provider = diagnostics_provider
        self.buffer_flusher = buffer_flusher
        self.audit_sink = audit_sink
        self.quarantine_dir = Path(quarantine_dir) if quarantine_dir else Path(r"C:\ProgramData\NetGuard\Quarantine")
        self.audit_log_path = Path(audit_log_path) if audit_log_path else Path(r"C:\ProgramData\NetGuard\response_audit.jsonl")
        self.quarantine_roots = [
            Path(item)
            for item in (
                quarantine_roots
                or [
                    Path.home(),
                    Path(r"C:\ProgramData"),
                    Path(r"C:\Windows\Temp"),
                    Path(os.environ.get("TEMP") or os.environ.get("TMP") or "."),
                ]
            )
        ]

    def execute(self, action: dict[str, Any]) -> EndpointResponseResult:
        action_type = str(action.get("action_type") or "").strip().lower()
        payload = action.get("payload") if isinstance(action.get("payload"), dict) else {}
        if action_type not in SUPPORTED_ACTIONS:
            return self._result("refused", action_type, {"error": "unsupported_action_type"})

        policy_ok, reason = self._verify_policy(action_type, action)
        if not policy_ok:
            return self._result("refused", action_type, {"error": reason})

        try:
            if action_type == "ping":
                return self._result("success", action_type, {"message": "pong"})
            if action_type == "collect_diagnostics":
                return self._result("success", action_type, self._collect_diagnostics())
            if action_type == "flush_buffer":
                return self._flush_buffer(action_type)
            if action_type == "isolate_host_simulated":
                return self._result(
                    "success",
                    action_type,
                    {
                        "simulated": True,
                        "message": "Host isolation simulation recorded; no firewall state was changed.",
                    },
                )
            if action_type == "safe_host_isolation":
                return self._safe_host_isolation(payload)
            if action_type == "rollback_host_isolation":
                return self._rollback_host_isolation(payload)
            if action_type == "block_ip_windows_firewall":
                return self._block_ip(payload)
            if action_type == "rollback_firewall_rule":
                return self._rollback_firewall_rule(payload)
            if action_type == "kill_process_guarded":
                return self._kill_process(payload)
            if action_type == "quarantine_file_guarded":
                return self._quarantine_file(payload)
        except Exception as exc:
            return self._result("failed", action_type, {"error": exc.__class__.__name__})
        return self._result("refused", action_type, {"error": "unsupported_action_type"})

    def _verify_policy(self, action_type: str, action: dict[str, Any]) -> tuple[bool, str]:
        payload = action.get("payload") if isinstance(action.get("payload"), dict) else {}
        policy = action.get("policy") if isinstance(action.get("policy"), dict) else payload.get("policy")
        if not isinstance(policy, dict):
            return False, "missing_policy"

        policy_host = str(policy.get("host_id") or "").strip()
        policy_tenant = str(policy.get("tenant_id") or "").strip()
        policy_action = str(policy.get("action_type") or "").strip().lower()
        if policy_host != self.host_id:
            return False, "policy_host_mismatch"
        if policy_tenant != self.tenant_id:
            return False, "policy_tenant_mismatch"
        if policy_action != action_type:
            return False, "policy_action_mismatch"

        return verify_response_policy(
            self.policy_secret,
            tenant_id=policy_tenant,
            host_id=policy_host,
            action_type=policy_action,
            nonce=policy.get("nonce"),
            expires_at=policy.get("expires_at"),
            signature=policy.get("signature"),
        )

    def _collect_diagnostics(self) -> dict[str, Any]:
        diagnostics = {
            "host_id": self.host_id,
            "tenant_id": self.tenant_id,
            "hostname": platform.node(),
            "platform": platform.system().lower(),
            "platform_version": platform.version(),
            "dry_run": self.dry_run,
            "generated_at": int(time.time()),
        }
        if self.diagnostics_provider:
            extra = self.diagnostics_provider()
            if isinstance(extra, dict):
                diagnostics.update(_safe_public_dict(extra))
        return diagnostics

    def _flush_buffer(self, action_type: str) -> EndpointResponseResult:
        if not self.buffer_flusher:
            return self._result("skipped", action_type, {"message": "buffer_flusher_not_configured"})
        flushed = self.buffer_flusher()
        return self._result("success", action_type, {"flushed": flushed})

    def _block_ip(self, payload: dict[str, Any]) -> EndpointResponseResult:
        target_ip = str(payload.get("ip") or payload.get("target") or payload.get("dst_ip") or "").strip()
        try:
            ipaddress.ip_address(target_ip)
        except ValueError:
            return self._result("refused", "block_ip_windows_firewall", {"error": "invalid_ip"})

        if self.dry_run:
            return self._result("skipped", "block_ip_windows_firewall", {"dry_run": True, "ip": target_ip})
        if platform.system().lower() != "windows":
            return self._result("skipped", "block_ip_windows_firewall", {"error": "windows_only", "ip": target_ip})

        rule_name = f"NetGuard Block {target_ip}"
        completed = subprocess.run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                "dir=out",
                "action=block",
                f"remoteip={target_ip}",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if completed.returncode != 0:
            return self._result(
                "failed",
                "block_ip_windows_firewall",
                {"error": "netsh_failed", "returncode": completed.returncode},
            )
        return self._result("success", "block_ip_windows_firewall", {"ip": target_ip, "rule_name": rule_name})

    def _rollback_firewall_rule(self, payload: dict[str, Any]) -> EndpointResponseResult:
        rule_name = str(payload.get("rule_name") or "").strip()
        target_ip = str(payload.get("ip") or payload.get("target") or "").strip()
        if not rule_name:
            try:
                ipaddress.ip_address(target_ip)
            except ValueError:
                return self._result("refused", "rollback_firewall_rule", {"error": "missing_rule_name_or_valid_ip"})
            rule_name = f"NetGuard Block {target_ip}"
        if not rule_name.startswith("NetGuard Block "):
            return self._result("refused", "rollback_firewall_rule", {"error": "rule_not_owned_by_netguard"})
        if self.dry_run:
            return self._result("skipped", "rollback_firewall_rule", {"dry_run": True, "rule_name": rule_name})
        if platform.system().lower() != "windows":
            return self._result("skipped", "rollback_firewall_rule", {"error": "windows_only", "rule_name": rule_name})

        completed = subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if completed.returncode != 0:
            return self._result("failed", "rollback_firewall_rule", {"error": "netsh_delete_failed", "returncode": completed.returncode})
        return self._result("success", "rollback_firewall_rule", {"rule_name": rule_name})

    def _safe_host_isolation(self, payload: dict[str, Any]) -> EndpointResponseResult:
        allowed_ips = _allowed_isolation_ips(payload)
        non_loopback_allowed = [ip for ip in allowed_ips if not ipaddress.ip_address(ip).is_loopback]
        if not non_loopback_allowed:
            return self._result("refused", "safe_host_isolation", {"error": "netguard_server_ip_required"})
        planned_rules = [f"NetGuard Isolation Allow {ip}" for ip in non_loopback_allowed]
        planned_rules.append("NetGuard Isolation Default Outbound Block")
        if self.dry_run:
            return self._result(
                "skipped",
                "safe_host_isolation",
                {
                    "dry_run": True,
                    "allowed_ips": allowed_ips,
                    "planned_rules": planned_rules,
                    "rollback_action": "rollback_host_isolation",
                },
            )
        if platform.system().lower() != "windows":
            return self._result("skipped", "safe_host_isolation", {"error": "windows_only", "allowed_ips": allowed_ips})
        if not payload.get("explicit_approval"):
            return self._result("refused", "safe_host_isolation", {"error": "explicit_approval_required"})

        previous_policy = _netsh_capture(["netsh", "advfirewall", "show", "currentprofile", "firewallpolicy"])
        created_rules: list[str] = []
        for ip in non_loopback_allowed:
            rule_name = f"NetGuard Isolation Allow {ip}"
            completed = subprocess.run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={rule_name}",
                    "dir=out",
                    "action=allow",
                    f"remoteip={ip}",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if completed.returncode != 0:
                return self._result(
                    "failed",
                    "safe_host_isolation",
                    {"error": "netsh_allow_rule_failed", "returncode": completed.returncode, "created_rules": created_rules},
                )
            created_rules.append(rule_name)

        completed = subprocess.run(
            ["netsh", "advfirewall", "set", "currentprofile", "firewallpolicy", "blockinbound,blockoutbound"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if completed.returncode != 0:
            return self._result(
                "failed",
                "safe_host_isolation",
                {"error": "netsh_isolation_policy_failed", "returncode": completed.returncode, "created_rules": created_rules},
            )
        return self._result(
            "success",
            "safe_host_isolation",
            {
                "allowed_ips": allowed_ips,
                "created_rules": created_rules,
                "previous_policy": previous_policy,
                "rollback_action": "rollback_host_isolation",
            },
        )

    def _rollback_host_isolation(self, payload: dict[str, Any]) -> EndpointResponseResult:
        allowed_ips = _allowed_isolation_ips(payload)
        rule_names = [
            str(item).strip()
            for item in (payload.get("rule_names") or payload.get("created_rules") or [])
            if str(item).strip()
        ]
        if not rule_names or any(key in payload for key in ("server_ip", "netguard_server_ip", "allowed_ips", "dns_ips", "dns_ip")):
            for ip in allowed_ips:
                if ipaddress.ip_address(ip).is_loopback:
                    continue
                rule_names.append(f"NetGuard Isolation Allow {ip}")
        rule_names = [item for item in dict.fromkeys(rule_names) if item.startswith("NetGuard Isolation ")]
        if self.dry_run:
            return self._result("skipped", "rollback_host_isolation", {"dry_run": True, "rule_names": rule_names})
        if platform.system().lower() != "windows":
            return self._result("skipped", "rollback_host_isolation", {"error": "windows_only", "rule_names": rule_names})
        if not payload.get("explicit_approval"):
            return self._result("refused", "rollback_host_isolation", {"error": "explicit_approval_required"})

        deleted: list[str] = []
        for rule_name in rule_names:
            completed = subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if completed.returncode == 0:
                deleted.append(rule_name)
        restore_policy = str(payload.get("restore_policy") or "blockinbound,allowoutbound").strip().lower()
        if restore_policy not in {"blockinbound,allowoutbound", "blockinbound,blockoutbound", "allowinbound,allowoutbound"}:
            return self._result("refused", "rollback_host_isolation", {"error": "invalid_restore_policy", "deleted_rules": deleted})
        completed = subprocess.run(
            ["netsh", "advfirewall", "set", "currentprofile", "firewallpolicy", restore_policy],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if completed.returncode != 0:
            return self._result(
                "failed",
                "rollback_host_isolation",
                {"error": "netsh_restore_policy_failed", "returncode": completed.returncode, "deleted_rules": deleted},
            )
        return self._result("success", "rollback_host_isolation", {"deleted_rules": deleted, "restore_policy": restore_policy})

    def _kill_process(self, payload: dict[str, Any]) -> EndpointResponseResult:
        process_name = _clean_process_name(payload.get("process_name"))
        try:
            pid = int(payload.get("pid"))
        except (TypeError, ValueError):
            return self._result("refused", "kill_process_guarded", {"error": "missing_pid"})
        if pid <= 0:
            return self._result("refused", "kill_process_guarded", {"error": "invalid_pid"})
        if not process_name:
            return self._result("refused", "kill_process_guarded", {"error": "missing_process_name"})
        if process_name in CRITICAL_PROCESSES:
            return self._result("refused", "kill_process_guarded", {"error": "protected_process", "process_name": process_name})
        if process_name in PROTECTED_PROCESSES and not payload.get("explicit_approval"):
            return self._result("refused", "kill_process_guarded", {"error": "explicit_approval_required", "process_name": process_name})
        if self.dry_run:
            return self._result("skipped", "kill_process_guarded", {"dry_run": True, "pid": pid, "process_name": process_name})

        if platform.system().lower() == "windows":
            completed = subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, text=True, timeout=15, check=False)
            if completed.returncode != 0:
                return self._result("failed", "kill_process_guarded", {"error": "taskkill_failed", "returncode": completed.returncode})
        else:
            os.kill(pid, 15)
        return self._result("success", "kill_process_guarded", {"pid": pid, "process_name": process_name})

    def _quarantine_file(self, payload: dict[str, Any]) -> EndpointResponseResult:
        raw_path = str(payload.get("path") or payload.get("file_path") or "").strip()
        expected_hash = str(payload.get("sha256") or payload.get("hash") or "").strip().lower()
        signature_checked = bool(payload.get("signature_checked") or payload.get("origin_checked"))
        if not raw_path:
            return self._result("refused", "quarantine_file_guarded", {"error": "missing_file_path"})
        if _has_path_traversal(raw_path):
            return self._result("refused", "quarantine_file_guarded", {"error": "path_traversal_refused"})
        if not expected_hash:
            return self._result("refused", "quarantine_file_guarded", {"error": "missing_sha256"})
        if not signature_checked:
            return self._result("refused", "quarantine_file_guarded", {"error": "missing_signature_check"})
        source_path = Path(raw_path)
        if not source_path.exists() or not source_path.is_file():
            return self._result("failed", "quarantine_file_guarded", {"error": "file_not_found"})
        resolved_source = source_path.resolve(strict=True)
        if not self._path_in_quarantine_scope(resolved_source) and not payload.get("explicit_approval"):
            return self._result(
                "refused",
                "quarantine_file_guarded",
                {"error": "quarantine_scope_requires_explicit_approval", "path": str(resolved_source)},
            )
        actual_hash = _sha256_file(source_path)
        if actual_hash.lower() != expected_hash:
            return self._result("refused", "quarantine_file_guarded", {"error": "sha256_mismatch"})
        if self.dry_run:
            return self._result("skipped", "quarantine_file_guarded", {"dry_run": True, "path": str(resolved_source)})

        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        quarantine_root = self.quarantine_dir.resolve()
        destination = (quarantine_root / f"{actual_hash[:16]}_{source_path.name}").resolve()
        if not _is_relative_to(destination, quarantine_root):
            return self._result("refused", "quarantine_file_guarded", {"error": "invalid_quarantine_destination"})
        shutil.move(str(resolved_source), str(destination))
        return self._result(
            "success",
            "quarantine_file_guarded",
            {
                "quarantine_path": str(destination),
                "sha256": actual_hash,
                "deleted": False,
            },
        )

    def _path_in_quarantine_scope(self, path: Path) -> bool:
        for root in self.quarantine_roots:
            try:
                resolved_root = root.resolve()
            except Exception:
                continue
            if _is_relative_to(path, resolved_root):
                return True
        return False

    def _result(self, status: str, action_type: str, result: dict[str, Any]) -> EndpointResponseResult:
        audit_event = {
            "audit_id": f"ngra_{uuid.uuid4().hex}",
            "timestamp": int(time.time()),
            "tenant_id": self.tenant_id,
            "host_id": self.host_id,
            "action_type": action_type,
            "status": status,
            "dry_run": self.dry_run,
        }
        if self.audit_sink:
            self.audit_sink(dict(audit_event))
        self._write_local_audit(audit_event)
        return EndpointResponseResult(status=status, action_type=action_type, result=dict(result or {}), audit_event=audit_event)

    def _write_local_audit(self, audit_event: dict[str, Any]) -> None:
        try:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(_safe_public_dict(audit_event), sort_keys=True) + "\n")
        except Exception:
            return


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _clean_process_name(value: Any) -> str:
    name = Path(str(value or "").strip()).name.lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def _safe_public_dict(value: dict[str, Any]) -> dict[str, Any]:
    redacted = {}
    for key, item in value.items():
        lowered = str(key).lower()
        if any(secret_word in lowered for secret_word in ("token", "secret", "password", "key")):
            continue
        redacted[str(key)] = item
    return redacted


def _has_path_traversal(value: str) -> bool:
    return any(part == ".." for part in Path(str(value or "")).parts)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _allowed_isolation_ips(payload: dict[str, Any]) -> list[str]:
    candidates: list[Any] = []
    for key in ("server_ip", "netguard_server_ip", "dns_ip"):
        if payload.get(key):
            candidates.append(payload.get(key))
    for key in ("allowed_ips", "dns_ips"):
        values = payload.get(key)
        if isinstance(values, list):
            candidates.extend(values)
    server_url = str(payload.get("server_url") or "").strip()
    if server_url:
        host = urlparse(server_url).hostname or ""
        candidates.append(host)
    candidates.extend(["127.0.0.1", "::1"])

    valid: list[str] = []
    for value in candidates:
        raw = str(value or "").strip()
        if not raw:
            continue
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        normalized = str(ip)
        if normalized not in valid:
            valid.append(normalized)
    return valid


def _netsh_capture(args: list[str]) -> str:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=15, check=False)
        return (completed.stdout or completed.stderr or "")[:1000]
    except Exception:
        return ""
