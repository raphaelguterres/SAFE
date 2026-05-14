"""Windows authentication telemetry for the SAFE endpoint agent.

The collector reads Windows Security events 4624 and 4625 through `wevtutil`.
It never changes system state and degrades safely when the agent lacks
permission to read the Security log.
"""

from __future__ import annotations

import logging
import platform
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Callable, Sequence


logger = logging.getLogger("netguard.agent.auth_logon")

LOGON_EVENT_IDS = {4624, 4625}


@dataclass(frozen=True)
class WindowsLogonEvent:
    event_id: int
    record_id: int
    timestamp: str
    user: str
    domain: str = ""
    source_ip: str = ""
    workstation: str = ""
    logon_type: str = ""
    outcome: str = "success"
    status: str = ""
    failure_reason: str = ""

    @property
    def event_type(self) -> str:
        return "login_failed" if self.event_id == 4625 else "login"

    @property
    def severity(self) -> str:
        return "medium" if self.event_id == 4625 else "low"

    @property
    def evidence(self) -> str:
        source = self.source_ip or self.workstation or "unknown source"
        return f"{self.event_type} for {self.user or 'unknown user'} from {source}"


@dataclass(frozen=True)
class LogonCollectionResult:
    events: list[WindowsLogonEvent]
    latest_record_id: int | None = None
    status: str = "ok"
    error: str = ""


Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


def collect_windows_logon_events(
    *,
    after_record_id: int | None = None,
    limit: int = 50,
    runner: Runner | None = None,
) -> LogonCollectionResult:
    """Collect recent Windows logon events without mutating endpoint state."""
    if platform.system().lower() != "windows":
        return LogonCollectionResult(events=[], status="unsupported_platform")

    count = max(1, min(int(limit or 50), 200))
    query = "*[System[(EventID=4624 or EventID=4625)]]"
    args = ["wevtutil", "qe", "Security", f"/q:{query}", "/f:xml", f"/c:{count}", "/rd:true"]
    execute = runner or _run_wevtutil
    try:
        completed = execute(args)
    except (OSError, subprocess.SubprocessError, TimeoutError) as exc:
        logger.debug("Windows logon telemetry unavailable: %s", exc)
        return LogonCollectionResult(events=[], status="unavailable", error=exc.__class__.__name__)

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()[:160]
        logger.debug("Windows logon telemetry refused: rc=%s err=%s", completed.returncode, stderr)
        return LogonCollectionResult(events=[], status="refused", error=stderr)

    parsed = parse_wevtutil_logon_xml(completed.stdout or "")
    if after_record_id is not None:
        parsed = [event for event in parsed if event.record_id > after_record_id]
    parsed.sort(key=lambda event: event.record_id)
    latest = max((event.record_id for event in parsed), default=after_record_id)
    return LogonCollectionResult(events=parsed, latest_record_id=latest, status="ok")


def parse_wevtutil_logon_xml(xml_text: str) -> list[WindowsLogonEvent]:
    """Parse one or more wevtutil XML event fragments."""
    if not xml_text.strip():
        return []

    wrapped = "<Events>" + xml_text.replace("<?xml version=\"1.0\" encoding=\"utf-16\"?>", "") + "</Events>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError:
        logger.debug("Could not parse Windows logon XML payload")
        return []

    events: list[WindowsLogonEvent] = []
    for node in list(root):
        parsed = _parse_event_node(node)
        if parsed:
            events.append(parsed)
    return events


def _run_wevtutil(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def _parse_event_node(node: ET.Element) -> WindowsLogonEvent | None:
    system = _find_child(node, "System")
    event_data = _find_child(node, "EventData")
    if system is None or event_data is None:
        return None

    event_id = _int_text(_find_child(system, "EventID"))
    if event_id not in LOGON_EVENT_IDS:
        return None

    record_id = _int_text(_find_child(system, "EventRecordID"))
    if record_id <= 0:
        return None

    time_node = _find_child(system, "TimeCreated")
    timestamp = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
    fields = _event_data_fields(event_data)
    user = fields.get("TargetUserName") or fields.get("SubjectUserName") or fields.get("UserName") or ""
    if user.endswith("$"):
        return None
    source_ip = fields.get("IpAddress") or fields.get("SourceNetworkAddress") or ""
    if source_ip in {"-", "::1", "127.0.0.1"}:
        source_ip = ""

    return WindowsLogonEvent(
        event_id=event_id,
        record_id=record_id,
        timestamp=timestamp,
        user=user,
        domain=fields.get("TargetDomainName") or fields.get("SubjectDomainName") or "",
        source_ip=source_ip,
        workstation=fields.get("WorkstationName") or "",
        logon_type=fields.get("LogonType") or "",
        outcome="failure" if event_id == 4625 else "success",
        status=fields.get("Status") or "",
        failure_reason=fields.get("FailureReason") or "",
    )


def _find_child(node: ET.Element, local_name: str) -> ET.Element | None:
    for child in list(node):
        if _local_name(child.tag) == local_name:
            return child
    return None


def _event_data_fields(event_data: ET.Element) -> dict[str, str]:
    fields: dict[str, str] = {}
    for child in list(event_data):
        if _local_name(child.tag) != "Data":
            continue
        name = child.attrib.get("Name")
        if not name:
            continue
        fields[name] = child.text or ""
    return fields


def _int_text(node: ET.Element | None) -> int:
    if node is None or node.text is None:
        return 0
    try:
        return int(str(node.text).strip())
    except ValueError:
        return 0


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


__all__ = [
    "WindowsLogonEvent",
    "LogonCollectionResult",
    "collect_windows_logon_events",
    "parse_wevtutil_logon_xml",
]
