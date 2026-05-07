"""Defensive process telemetry collector for the SAFE endpoint agent."""

from __future__ import annotations

import hashlib
import os
import platform
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

try:  # pragma: no cover - availability depends on the endpoint image
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore


@dataclass(slots=True)
class ProcessTelemetry:
    process_name: str
    pid: int
    parent_pid: int | None
    command_line: str
    sha256: str = ""
    signer_info: str = "unknown"
    execution_timestamp: str = ""
    integrity_level: str = "unknown"
    username: str = ""
    executable_path: str = ""
    collection_status: str = "ok"
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def collect_process_telemetry(
    *,
    limit: int = 500,
    include_hashes: bool = True,
    hash_max_bytes: int = 64 * 1024 * 1024,
    processes: Iterable[Any] | None = None,
) -> list[dict[str, Any]]:
    """Collect process telemetry without invasive memory reads."""

    limit = max(1, min(int(limit), 2000))
    snapshots: list[ProcessTelemetry] = []
    source = list(processes) if processes is not None else _iter_psutil_processes()
    for proc in source[:limit]:
        snapshots.append(_snapshot_process(proc, include_hashes=include_hashes, hash_max_bytes=hash_max_bytes))
    if not snapshots and processes is None:
        snapshots.append(
            ProcessTelemetry(
                process_name=Path(os.environ.get("ComSpec") or "python").name,
                pid=os.getpid(),
                parent_pid=None,
                command_line="",
                execution_timestamp=_utc_now(),
                collection_status="degraded",
                errors=["psutil_unavailable"],
            )
        )
    return [item.to_dict() for item in snapshots]


def build_process_batch(host_id: str, tenant_id: str = "", *, limit: int = 500) -> dict[str, Any]:
    return {
        "host_id": str(host_id or ""),
        "tenant_id": str(tenant_id or ""),
        "source": "netguard-agent",
        "event_type": "process_telemetry_batch",
        "timestamp": _utc_now(),
        "processes": collect_process_telemetry(limit=limit),
    }


def _iter_psutil_processes() -> list[Any]:
    if psutil is None:
        return []
    try:
        return list(psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "status"]))
    except Exception:
        return []


def _snapshot_process(proc: Any, *, include_hashes: bool, hash_max_bytes: int) -> ProcessTelemetry:
    errors: list[str] = []
    info = getattr(proc, "info", None) or {}
    if not isinstance(info, dict):
        info = {}
    pid = _int(info.get("pid") if info else getattr(proc, "pid", 0))
    ppid = _int_or_none(info.get("ppid"))
    name = str(info.get("name") or _safe_call(proc, "name") or "unknown")
    exe = str(info.get("exe") or _safe_call(proc, "exe") or "")
    cmdline_value = info.get("cmdline")
    if cmdline_value is None:
        cmdline_value = _safe_call(proc, "cmdline") or []
    command_line = " ".join(str(item) for item in cmdline_value) if isinstance(cmdline_value, list) else str(cmdline_value or "")
    username = str(info.get("username") or _safe_call(proc, "username") or "")
    create_time = info.get("create_time") or _safe_call(proc, "create_time")
    sha256 = ""
    if include_hashes and exe:
        try:
            sha256 = sha256_file(Path(exe), max_bytes=hash_max_bytes)
        except Exception as exc:
            errors.append(f"hash_unavailable:{exc.__class__.__name__}")
    return ProcessTelemetry(
        process_name=name,
        pid=pid,
        parent_pid=ppid,
        command_line=command_line[:4096],
        sha256=sha256,
        signer_info=_signer_info(exe),
        execution_timestamp=_timestamp_from_epoch(create_time),
        integrity_level=_integrity_level(),
        username=username,
        executable_path=exe,
        collection_status="degraded" if errors else "ok",
        errors=errors,
    )


def sha256_file(path: Path, *, max_bytes: int = 64 * 1024 * 1024) -> str:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        return ""
    if resolved.stat().st_size > max_bytes:
        return ""
    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _signer_info(executable_path: str) -> str:
    if not executable_path:
        return "unknown"
    if platform.system().lower() != "windows":
        return "not_available"
    return "not_collected"


def _integrity_level() -> str:
    if platform.system().lower() != "windows":
        return "not_available"
    return "unknown"


def _safe_call(obj: Any, method_name: str) -> Any:
    method = getattr(obj, method_name, None)
    if not callable(method):
        return None
    try:
        return method()
    except Exception:
        return None


def _timestamp_from_epoch(value: Any) -> str:
    try:
        epoch = float(value)
    except (TypeError, ValueError):
        return ""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
