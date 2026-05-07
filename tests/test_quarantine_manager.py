from __future__ import annotations

import hashlib

import pytest

from agent.quarantine_manager import QuarantineManager


def test_quarantine_manager_moves_and_restores_file(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"netguard evidence")
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    manager = QuarantineManager(tmp_path / "quarantine", tenant_id="tenant-a", host_id="host-a", allowed_roots=[tmp_path])

    record = manager.quarantine_file(sample, expected_sha256=digest)

    assert not sample.exists()
    assert record.sha256 == digest
    assert manager.get_record(record.quarantine_id) is not None

    restored = manager.restore(record.quarantine_id)

    assert restored.restored_at
    assert sample.exists()


def test_quarantine_manager_rejects_path_traversal(tmp_path):
    manager = QuarantineManager(tmp_path / "quarantine", allowed_roots=[tmp_path])

    with pytest.raises(ValueError, match="path_traversal_refused"):
        manager.quarantine_file(tmp_path / ".." / "evil.bin")
