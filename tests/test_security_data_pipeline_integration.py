from xdr.pipeline import XDRPipeline
from xdr.schema import EndpointEvent


def test_xdr_pipeline_exposes_canonical_enriched_event_and_lineage():
    outcome = XDRPipeline().process_event(
        EndpointEvent.from_payload(
            {
                "tenant_id": "tenant-a",
                "host_id": "host-1",
                "event_type": "process_execution",
                "process_name": "powershell.exe",
                "command_line": "powershell -enc AAAA",
                "severity": "high",
                "source": "agent",
                "timestamp": "2026-05-11T00:00:00Z",
            }
        )
    )
    data = outcome.to_dict()

    assert data["canonical_event"]["tenant_id"] == "tenant-a"
    assert data["enriched_event"]["event_type"] == "process_execution"
    assert data["event_lineage"]["step_count"] >= 1
