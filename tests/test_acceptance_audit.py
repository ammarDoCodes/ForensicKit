from pathlib import Path

from forensickit.analysis import analyze_case, load_case, pivot, replay
from forensickit.manifest import detect_format
from forensickit.util import safe_archive_member


def test_manifest_provenance_and_references(tmp_path: Path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    source = evidence / "records.txt"
    source.write_text(
        '{"event_type":"logon","timestamp":"2026-01-01T00:00:00-05:00","host":"h","user":"a","session_id":"s"}\n'
        '{"event_type":"logon","timestamp":"2026-01-01T00:00:01-05:00","host":"h","user":"b","session_id":"s"}\n'
        '{"event_type":"network_connection","timestamp":"not-a-time","host":"h","remote_ip":"192.0.2.1"}\n',
        encoding="utf-8",
    )
    result = analyze_case(tmp_path / "case", evidence)
    data = load_case(tmp_path / "case")
    assert detect_format(source.read_bytes(), source.suffix) == "jsonl-evidence"
    assert data["manifest"]["import_batch_id"]
    assert all(event["provenance"]["import_batch_id"] == data["manifest"]["import_batch_id"] for event in data["events"])
    assert any(item["type"] == "incompatible_session_attribution" for item in data["contradictions"])
    assert any(item["code"] == "INVALID_TIMESTAMP" for item in data["warnings"])
    entity_ids = {entity["entity_id"] for entity in data["entities"]}
    event_ids = {event["event_id"] for event in data["events"]}
    relationship_ids = {relationship["relationship_id"] for relationship in data["relationships"]}
    assert all(relationship["from"] in entity_ids and relationship["to"] in entity_ids for relationship in data["relationships"])
    assert all(set(relationship["evidence_ids"]) <= event_ids for relationship in data["relationships"])
    assert all(set(thread["event_ids"]) <= event_ids and set(thread["relationship_ids"]) <= relationship_ids for thread in data["threads"])
    assert result["warnings"]


def test_pivot_and_replay_expose_review_state(tmp_path: Path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "records.jsonl").write_text(
        '{"event_type":"logon","timestamp":"2026-01-01","host":"h","user":"a","session_id":"s"}\n'
        '{"event_type":"process_start","timestamp":"2026-01-01T00:00:01Z","host":"h","user":"a","session_id":"s","pid":7,"image":"x.exe"}\n',
        encoding="utf-8",
    )
    result = analyze_case(tmp_path / "case", evidence)
    assert result["threads"]
    session = next(entity["entity_id"] for entity in result["entities"] if entity["type"] == "session")
    pivoted = pivot(tmp_path / "case", session)
    assert pivoted["event_ids"] and "hypothesis_ids" in pivoted
    replayed = replay(tmp_path / "case", result["threads"][0]["thread_id"])
    assert replayed["time_uncertain"]
    assert replayed["uncertain_event_ids"]


def test_archive_member_and_content_detection():
    assert safe_archive_member("evidence/records.jsonl")
    assert not safe_archive_member("../outside")
    assert not safe_archive_member("C:/outside")
    assert detect_format(b"<xml />\n", ".jsonl") == "windows-event-xml"


def test_explicit_device_file_correlation(tmp_path: Path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "records.jsonl").write_text(
        '{"event_type":"device_connect","timestamp":"2026-01-01T00:00:00Z","host":"h","device_id":"usb-1"}\n'
        '{"event_type":"file_create","timestamp":"2026-01-01T00:00:02Z","host":"h","device_id":"usb-1","file_path":"E:\\\\x.exe"}\n',
        encoding="utf-8",
    )
    result = analyze_case(tmp_path / "case", evidence)
    assert any(item["type"] == "device_file_observation" for item in result["relationships"])
