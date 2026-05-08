import pytest

from xdr.case_management import CaseRepository


def test_case_repository_enforces_tenant_scope_and_lifecycle():
    repo = CaseRepository()
    case = repo.create_case(
        tenant_id="tenant-a",
        title="Encoded PowerShell investigation",
        severity="high",
        created_by="analyst-a",
        related_hosts=["host-1"],
    )
    repo.create_case(tenant_id="tenant-b", title="Other tenant", severity="critical")

    assert repo.get_case(case.case_id, tenant_id="tenant-a") is not None
    assert repo.get_case(case.case_id, tenant_id="tenant-b") is None

    updated = repo.update_status(case.case_id, tenant_id="tenant-a", status="investigating", actor="analyst-a")
    assert updated.status == "investigating"
    assert any(item.event_type == "status_changed" for item in updated.timeline)


def test_case_repository_notes_evidence_and_watchers_are_auditable():
    repo = CaseRepository()
    case = repo.create_case(tenant_id="tenant-a", title="Case", severity="medium")

    note = repo.add_note(case.case_id, tenant_id="tenant-a", author="analyst", body="Validated process tree.")
    evidence = repo.pin_evidence(
        case.case_id,
        tenant_id="tenant-a",
        evidence_id="ev-1",
        evidence_type="process",
        title="PowerShell process",
        actor="analyst",
    )
    watched = repo.add_watcher(case.case_id, tenant_id="tenant-a", watcher="soc-lead")

    assert note.body == "Validated process tree."
    assert evidence.evidence_id == "ev-1"
    assert "soc-lead" in watched.watchers
    with pytest.raises(KeyError):
        repo.add_note(case.case_id, tenant_id="tenant-b", author="analyst", body="cross tenant")
