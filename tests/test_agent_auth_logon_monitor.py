import subprocess

from agent.auth_logon_monitor import (
    LogonCollectionResult,
    WindowsLogonEvent,
    collect_windows_logon_events,
    parse_wevtutil_logon_xml,
)
from agent.collector import TelemetryCollector


SAMPLE_LOGON_XML = """
<Event>
  <System>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-05-14T12:00:00Z" />
    <EventRecordID>101</EventRecordID>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="TargetDomainName">SAFE</Data>
    <Data Name="IpAddress">203.0.113.10</Data>
    <Data Name="WorkstationName">WS-01</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="Status">0xC000006D</Data>
    <Data Name="FailureReason">Unknown user name or bad password.</Data>
  </EventData>
</Event>
<Event>
  <System>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-05-14T12:05:00Z" />
    <EventRecordID>102</EventRecordID>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="IpAddress">10.0.0.5</Data>
    <Data Name="WorkstationName">WS-01</Data>
    <Data Name="LogonType">10</Data>
  </EventData>
</Event>
"""


def test_parse_wevtutil_logon_xml_extracts_identity_events():
    events = parse_wevtutil_logon_xml(SAMPLE_LOGON_XML)

    assert [event.event_type for event in events] == ["login_failed", "login"]
    assert events[0].user == "alice"
    assert events[0].source_ip == "203.0.113.10"
    assert events[0].severity == "medium"
    assert events[1].record_id == 102


def test_collect_windows_logon_events_filters_seen_records(monkeypatch):
    monkeypatch.setattr("agent.auth_logon_monitor.platform.system", lambda: "Windows")

    def runner(args):
        assert "wevtutil" in args[0]
        return subprocess.CompletedProcess(args=list(args), returncode=0, stdout=SAMPLE_LOGON_XML, stderr="")

    result = collect_windows_logon_events(after_record_id=101, runner=runner)

    assert result.status == "ok"
    assert len(result.events) == 1
    assert result.events[0].record_id == 102
    assert result.latest_record_id == 102


def test_collector_baselines_auth_events_then_emits_new_events(monkeypatch):
    calls = [
        LogonCollectionResult(
            events=[WindowsLogonEvent(event_id=4625, record_id=200, timestamp="2026-05-14T12:00:00Z", user="alice")],
            latest_record_id=200,
        ),
        LogonCollectionResult(
            events=[WindowsLogonEvent(event_id=4625, record_id=201, timestamp="2026-05-14T12:01:00Z", user="alice")],
            latest_record_id=201,
        ),
    ]

    def fake_collect(**kwargs):
        return calls.pop(0)

    monkeypatch.setattr("agent.auth_logon_monitor.collect_windows_logon_events", fake_collect)
    collector = TelemetryCollector(
        host_id="host-1",
        host_facts={"hostname": "WS-01", "platform": "windows"},
        collect_processes=False,
        collect_connections=False,
        collect_security=False,
        collect_auth_events=True,
    )

    assert collector._collect_auth_events() == []
    events = collector._collect_auth_events()

    assert len(events) == 1
    assert events[0]["event_type"] == "login_failed"
    assert events[0]["user"] == "alice"
    assert events[0]["mitre_technique"] == "T1110"
    assert events[0]["details"]["event_record_id"] == 201
