"""Safe reversible file quarantine for SAFE endpoint response."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class QuarantineRecord:
    quarantine_id: str
    original_path: str
    quarantine_path: str
    sha256: str
    tenant_id: str = ""
    host_id: str = ""
    created_at: str = ""
    restored_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class QuarantineManager:
    """Moves suspicious files into a controlled folder and supports restore."""

    def __init__(
        self,
        quarantine_dir: str | Path | None = None,
        *,
        tenant_id: str = "",
        host_id: str = "",
        allowed_roots: list[str | Path] | None = None,
    ):
        self.quarantine_dir = Path(quarantine_dir) if quarantine_dir else Path(r"C:\ProgramData\NetGuard\Quarantine")
        self.tenant_id = str(tenant_id or "")
        self.host_id = str(host_id or "")
        self.allowed_roots = [
            Path(item)
            for item in (
                allowed_roots
                or [
                    Path.home(),
                    Path(r"C:\ProgramData"),
                    Path(os.environ.get("TEMP") or os.environ.get("TMP") or "."),
                ]
            )
        ]

    def quarantine_file(
        self,
        path: str | Path,
        *,
        expected_sha256: str = "",
        metadata: dict[str, Any] | None = None,
        explicit_approval: bool = False,
    ) -> QuarantineRecord:
        source = self._validate_source_path(path, explicit_approval=explicit_approval)
        actual_hash = sha256_file(source)
        if expected_sha256 and actual_hash.lower() != str(expected_sha256).lower():
            raise ValueError("sha256_mismatch")

        quarantine_id = f"ngq_{uuid.uuid4().hex}"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        quarantine_root = self.quarantine_dir.resolve()
        destination = (quarantine_root / f"{quarantine_id}_{source.name}").resolve()
        if not _is_relative_to(destination, quarantine_root):
            raise ValueError("invalid_quarantine_destination")

        shutil.move(str(source), str(destination))
        record = QuarantineRecord(
            quarantine_id=quarantine_id,
            original_path=str(source),
            quarantine_path=str(destination),
            sha256=actual_hash,
            tenant_id=self.tenant_id,
            host_id=self.host_id,
            created_at=_utc_now(),
            metadata=_safe_metadata(metadata or {}),
        )
        self._write_metadata(record)
        return record

    def restore(self, quarantine_id: str, *, restore_path: str | Path | None = None, explicit_approval: bool = False) -> QuarantineRecord:
        record = self.get_record(quarantine_id)
        if not record:
            raise FileNotFoundError("quarantine_record_not_found")
        quarantined = Path(record.quarantine_path).resolve(strict=True)
        destination = Path(restore_path or record.original_path)
        if _has_path_traversal(str(destination)):
            raise ValueError("path_traversal_refused")
        if destination.exists() and not explicit_approval:
            raise ValueError("restore_destination_exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(quarantined), str(destination))
        record.restored_at = _utc_now()
        record.quarantine_path = str(quarantined)
        record.original_path = str(destination.resolve())
        self._write_metadata(record)
        return record

    def get_record(self, quarantine_id: str) -> QuarantineRecord | None:
        qid = _safe_id(quarantine_id)
        if not qid:
            return None
        metadata_path = self.quarantine_dir / f"{qid}.json"
        if not metadata_path.exists():
            return None
        with metadata_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return QuarantineRecord(**data)

    def list_records(self) -> list[dict[str, Any]]:
        if not self.quarantine_dir.exists():
            return []
        records = []
        for metadata_path in sorted(self.quarantine_dir.glob("ngq_*.json")):
            try:
                with metadata_path.open("r", encoding="utf-8") as handle:
                    records.append(json.load(handle))
            except Exception:
                continue
        return records

    def _validate_source_path(self, path: str | Path, *, explicit_approval: bool) -> Path:
        raw = str(path or "").strip()
        if not raw:
            raise ValueError("missing_file_path")
        if _has_path_traversal(raw):
            raise ValueError("path_traversal_refused")
        source = Path(raw).resolve(strict=True)
        if not source.is_file():
            raise FileNotFoundError("file_not_found")
        if not explicit_approval and not any(_is_relative_to(source, _safe_resolve(root)) for root in self.allowed_roots):
            raise PermissionError("quarantine_scope_requires_explicit_approval")
        return source

    def _write_metadata(self, record: QuarantineRecord) -> None:
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        metadata_path = self.quarantine_dir / f"{record.quarantine_id}.json"
        with metadata_path.open("w", encoding="utf-8") as handle:
            json.dump(record.to_dict(), handle, indent=2, sort_keys=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_id(value: str) -> str:
    text = str(value or "").strip()
    if not text.startswith("ngq_"):
        return ""
    return "".join(char for char in text if char.isalnum() or char == "_")


def _safe_metadata(value: dict[str, Any]) -> dict[str, Any]:
    clean = {}
    for key, item in value.items():
        lowered = str(key).lower()
        if any(marker in lowered for marker in ("token", "secret", "password", "key")):
            continue
        clean[str(key)] = item
    return clean


def _has_path_traversal(value: str) -> bool:
    return any(part == ".." for part in Path(str(value or "")).parts)


def _safe_resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except Exception:
        return path


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
