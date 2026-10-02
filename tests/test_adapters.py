import json
from pathlib import Path

import forensickit.adapters as adapters
from forensickit.adapters import parse_evidence
from forensickit.manifest import detect_format


def test_json_array_and_csv_adapters():
    array = b'[{"event_type":"logon","timestamp":"2026-01-01T00:00:00Z","host":"h","user":"u"}]'
    assert detect_format(array, ".json") == "json-array-evidence"
    events, warnings = parse_evidence(array, "file-array", "records.json", "json-array-evidence", "batch-1")
    assert len(events) == 1 and not warnings
    assert events[0]["provenance"]["parser"] == "json-array-evidence"

    csv_data = b"event_type,timestamp,host,pid,image\nprocess_start,2026-01-01T00:00:00Z,h,7,x.exe\n"
    assert detect_format(csv_data, ".csv") == "csv-evidence"
    events, warnings = parse_evidence(csv_data, "file-csv", "records.csv", "csv-evidence", "batch-1")
    assert len(events) == 1 and not warnings
    assert events[0]["attributes"]["pid"] == "7"

    sysmon = b'{"EventID":3,"UtcTime":"2026-01-01T00:00:00Z","Computer":"host-a","ProcessId":7,"DestinationIp":"192.0.2.10"}'
    assert detect_format(sysmon, ".json") == "sysmon-json"
    events, warnings = parse_evidence(sysmon, "file-sysmon", "sysmon.json", "sysmon-json", "batch-1")
    assert len(events) == 1 and not warnings
    assert events[0]["event_type"] == "network_connection"


def test_windows_and_sysmon_xml_adapters_reject_entities_and_map_events():
    xml = b"""<Events><Event><System><EventID>4688</EventID><TimeCreated SystemTime=\"2026-01-01T00:00:00Z\"/><Computer>host-a</Computer></System><EventData><Data Name=\"NewProcessId\">7</Data><Data Name=\"NewProcessName\">x.exe</Data><Data Name=\"ParentProcessId\">1</Data></EventData></Event></Events>"""
    events, warnings = parse_evidence(xml, "file-xml", "events.xml", "windows-event-xml", "batch-1")
    assert len(events) == 1 and not warnings
    assert events[0]["event_type"] == "process_start"
    assert events[0]["provenance"]["parser"] == "windows-event-xml"

    hostile = b"<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///secret'> ]><Events/>"
    events, warnings = parse_evidence(hostile, "file-hostile", "events.xml", "windows-event-xml", "batch-1")
    assert not events
    assert warnings[0]["code"] == "XML_EXTERNAL_ENTITY_REJECTED"


def test_malformed_encoding_is_isolated():
    events, warnings = parse_evidence(b"\xff\xfe", "file-bad", "events.csv", "csv-evidence", "batch-1")
    assert not events
    assert warnings[0]["code"] == "INVALID_ENCODING"


def test_non_jsonl_adapters_enforce_record_bound():
    original_limit = adapters.MAX_RECORD_COUNT
    adapters.MAX_RECORD_COUNT = 1
    try:
        array = b'[{"event_type":"logon","timestamp":"2026-01-01T00:00:00Z"},{"event_type":"logon","timestamp":"2026-01-01T00:00:01Z"}]'
        events, warnings = parse_evidence(array, "file-array", "records.json", "json-array-evidence", "batch-1")
        assert len(events) == 1 and warnings[0]["code"] == "RECORD_COUNT_LIMIT"

        csv_data = b"event_type,timestamp\nlogon,2026-01-01T00:00:00Z\nlogon,2026-01-01T00:00:01Z\n"
        events, warnings = parse_evidence(csv_data, "file-csv", "records.csv", "csv-evidence", "batch-1")
        assert len(events) == 1 and warnings[0]["code"] == "RECORD_COUNT_LIMIT"

        xml = b"<Events><Event><System><EventID>4624</EventID><TimeCreated SystemTime=\"2026-01-01T00:00:00Z\"/></System></Event><Event><System><EventID>4624</EventID><TimeCreated SystemTime=\"2026-01-01T00:00:01Z\"/></System></Event></Events>"
        events, warnings = parse_evidence(xml, "file-xml", "events.xml", "windows-event-xml", "batch-1")
        assert len(events) == 1 and warnings[0]["code"] == "RECORD_COUNT_LIMIT"
    finally:
        adapters.MAX_RECORD_COUNT = original_limit
