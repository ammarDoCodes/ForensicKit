import json
import hashlib
import sys
import types
from pathlib import Path
from unittest.mock import patch

from forensickit.analysis import analyze_case
from forensickit.evtx import parse_evtx, parse_evtx_xml_records


ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "evtx"


def _xml_records():
    names = (("record-4624.xml", "1001"), ("record-4688.xml", "1002"), ("record-4104.xml", "1003"), ("record-3.xml", "1004"))
    return [((FIXTURES / name).read_text(encoding="utf-8"), record_id) for name, record_id in names]


def test_evtx_xml_field_mapping_timestamps_and_provenance():
    events, diagnostics = parse_evtx_xml_records(_xml_records(), "file-evtx", "security.evtx", "batch-evtx")
    assert not diagnostics
    assert [event["event_type"] for event in events] == ["logon", "process_start", "powershell_activity", "network_connection"]
    assert events[0]["attributes"]["session_id"] == "0x100"
    assert {item["entity_id"] for item in events[0]["entities"] if item["entity_id"].startswith("user:")} == {"user:lab-win-01:alice"}
    process = events[1]
    assert process["attributes"]["pid"] == "4660"
    assert process["attributes"]["parent_pid"] == "1111"
    assert {item["entity_id"] for item in process["entities"] if item["entity_id"].startswith("user:")} == {"user:lab-win-01:alice"}
    assert process["attributes"]["image"]
    assert process["observed_at"] == {
        "original": "2026-09-21T16:42:00.000Z",
        "utc": "2026-09-21T16:42:00Z",
        "precision": "second",
        "quality": "exact",
        "timezone_source": "record-offset",
    }
    assert process["provenance"]["parser"] == "evtx"
    assert process["provenance"]["parser_version"] == "1.1.0"
    assert process["provenance"]["source_file_id"] == "file-evtx"
    assert process["provenance"]["source_locator"] == "evtx-record[1002]"
    assert process["provenance"]["event_record_id"] == "1002"
    assert process["provenance"]["record_fingerprint"].startswith("sha256:")
    assert process["source_payload"]["event_record_id"] == "1002"

    additional = [
        """<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2026-09-21T16:45:00Z"/><Computer>LAB-WIN-01</Computer></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="TargetLogonId">0x101</Data></EventData></Event>""",
        """<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><TimeCreated SystemTime="2026-09-21T16:46:00Z"/><Computer>LAB-WIN-01</Computer></System><EventData><Data Name="ProcessId">4661</Data><Data Name="Image">cmd.exe</Data></EventData></Event>""",
        """<Event><System><Provider Name="Microsoft-Windows-PowerShell"/><EventID>4103</EventID><TimeCreated SystemTime="2026-09-21T16:47:00Z"/><Computer>LAB-WIN-01</Computer></System><EventData><Data Name="User">alice</Data><Data Name="LogonId">0x100</Data></EventData></Event>""",
    ]
    additional_events, additional_diagnostics = parse_evtx_xml_records(additional, "file-evtx", "security.evtx", "batch-evtx")
    assert [event["event_type"] for event in additional_events] == ["logon_failure", "process_start", "powershell_activity"]
    assert not additional_diagnostics


def test_evtx_xml_parsing_is_deterministic_and_reports_incomplete_records():
    first, first_diagnostics = parse_evtx_xml_records(_xml_records(), "file-evtx", "security.evtx", "batch-evtx")
    second, second_diagnostics = parse_evtx_xml_records(list(reversed(_xml_records())), "file-evtx", "security.evtx", "batch-evtx")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first_diagnostics == second_diagnostics == []
    missing = """<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>4624</EventID><Computer>LAB-WIN-01</Computer></System><EventData /></Event>"""
    malformed = (FIXTURES / "malformed.xml").read_text(encoding="utf-8")
    _, diagnostics = parse_evtx_xml_records([(missing, "2001"), (malformed, "2002")], "file-evtx", "security.evtx", "batch-evtx")
    codes = {item["code"] for item in diagnostics}
    assert {"MISSING_TIMESTAMP", "EVTX_INCOMPLETE_LOGON", "MALFORMED_EVTX_RECORD"}.issubset(codes)


def test_evtx_optional_dependency_missing_is_clear():
    events, diagnostics = parse_evtx(b"ElfFile\x00fixture", "file-evtx", "security.evtx", "batch-evtx", _dependency_loader=lambda: None)
    assert events == []
    assert diagnostics[0]["code"] == "OPTIONAL_DEPENDENCY_MISSING"
    assert "optional dependency" in diagnostics[0]["message"]


def test_evtx_security_bounds_and_unsupported_fields():
    hostile = "<!DOCTYPE Event [ <!ENTITY xxe SYSTEM 'file:///secret'> ]><Event/>"
    events, diagnostics = parse_evtx_xml_records([hostile], "file-evtx", "security.evtx", "batch-evtx")
    assert not events
    assert diagnostics[0]["code"] == "XML_EXTERNAL_ENTITY_REJECTED"

    events, diagnostics = parse_evtx_xml_records([b"\xff\xfe"], "file-evtx", "security.evtx", "batch-evtx")
    assert not events
    assert diagnostics[0]["code"] == "INVALID_ENCODING"

    unsupported = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>9999</EventID><TimeCreated SystemTime="2026-09-21T16:45:00Z"/></System></Event>"""
    events, diagnostics = parse_evtx_xml_records([unsupported], "file-evtx", "security.evtx", "batch-evtx")
    assert not events
    assert diagnostics[0]["code"] == "UNSUPPORTED_EVTX_EVENT_ID"

    oversized = "<Event><System><EventID>4624</EventID></System><EventData><Data Name='TargetUserName'>" + ("x" * (2 * 1024 * 1024)) + "</Data></EventData></Event>"
    events, diagnostics = parse_evtx_xml_records([oversized], "file-evtx", "security.evtx", "batch-evtx")
    assert not events
    assert diagnostics[0]["code"] == "EVTX_RECORD_TOO_LARGE"

    events, diagnostics = parse_evtx(b"not-evtx", "file-evtx", "security.evtx", "batch-evtx", _dependency_loader=lambda: None)
    assert not events
    assert diagnostics[0]["code"] == "MALFORMED_EVTX_HEADER"

def test_evtx_decoder_shim_enters_existing_analysis_relationships_and_threads(tmp_path: Path):
    class FakeRecord:
        def __init__(self, xml, record_id):
            self._xml = xml
            self._record_id = record_id

        def xml(self):
            return self._xml

        def record_num(self):
            return self._record_id

    fixture_records = [FakeRecord(xml, record_id) for xml, record_id in _xml_records()]

    class FakeEvtx:
        def __init__(self, path):
            assert Path(path).suffix == ".evtx"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return None

        def records(self):
            return iter(fixture_records)

    fake_package = types.ModuleType("Evtx")
    fake_module = types.ModuleType("Evtx.Evtx")
    fake_package.Evtx = FakeEvtx
    fake_module.Evtx = FakeEvtx
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    source = evidence / "security.evtx"
    source.write_bytes(b"ElfFile\x00fixture")
    before = source.read_bytes()
    with patch.dict(sys.modules, {"Evtx": fake_package, "Evtx.Evtx": fake_module}):
        result = analyze_case(tmp_path / "case", evidence)
    assert source.read_bytes() == before
    assert result["manifest"]["inputs"][0]["sha256"] == hashlib.sha256(before).hexdigest()
    assert all(event["provenance"]["source_file_sha256"] == hashlib.sha256(before).hexdigest() for event in result["events"])
    assert len(result["events"]) == 4
    assert any(item["type"] == "process_network_link" for item in result["relationships"])
    assert result["threads"]
    assert all(event["provenance"]["parser"] == "evtx" for event in result["events"])
    assert result["manifest"]["inputs"][0]["detected_format"] == "evtx"
