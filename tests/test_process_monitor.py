from __future__ import annotations

from agent.process_monitor import build_process_batch, collect_process_telemetry


class FakeProc:
    info = {
        "pid": 1234,
        "ppid": 100,
        "name": "powershell.exe",
        "exe": "",
        "cmdline": ["powershell.exe", "-NoProfile"],
        "username": "user-a",
        "create_time": 1_777_777_777,
    }


def test_process_monitor_collects_expected_shape_without_hashing():
    rows = collect_process_telemetry(processes=[FakeProc()], include_hashes=False)

    assert rows[0]["process_name"] == "powershell.exe"
    assert rows[0]["pid"] == 1234
    assert rows[0]["parent_pid"] == 100
    assert "powershell.exe" in rows[0]["command_line"]
    assert rows[0]["collection_status"] == "ok"


def test_process_monitor_builds_batch():
    batch = build_process_batch("host-proc", "tenant-a", limit=1)

    assert batch["host_id"] == "host-proc"
    assert batch["tenant_id"] == "tenant-a"
    assert batch["source"] == "netguard-agent"
    assert isinstance(batch["processes"], list)
