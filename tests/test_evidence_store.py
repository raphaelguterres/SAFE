import pytest

from xdr.evidence_store import EvidenceStore


def test_evidence_store_is_immutable_redacted_and_tenant_scoped():
    store = EvidenceStore()
    first = store.add_evidence(
        tenant_id="tenant-a",
        evidence_type="telemetry",
        title="Raw event",
        data={"event_id": "evt-1", "api_key": "secret"},
        created_by="analyst",
        linked_case_id="case-1",
    )
    store.add_evidence(
        tenant_id="tenant-b",
        evidence_type="telemetry",
        title="Other",
        data={"event_id": "evt-2"},
        created_by="analyst",
    )

    assert first.data["api_key"] == "[redacted]"
    with pytest.raises(TypeError):
        first.data["event_id"] = "tamper"
    assert len(store.list_evidence(tenant_id="tenant-a")) == 1
    assert store.verify_integrity(tenant_id="tenant-a")["valid"] is True
    assert store.verify_integrity()["valid"] is True


def test_evidence_store_requires_object_data():
    store = EvidenceStore()
    with pytest.raises(ValueError):
        store.add_evidence(
            tenant_id="tenant-a",
            evidence_type="telemetry",
            title="Bad",
            data=[],
            created_by="analyst",
        )
