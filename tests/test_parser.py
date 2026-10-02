from forensickit.parser import parse_jsonl
def test_parser_is_provenance_preserving_and_warns_per_record():
    events, warnings = parse_jsonl(b'{"event_type":"process_start","timestamp":"2026-01-01T00:00:00Z","host":"h","pid":1}\nnot json\n', "file-1", "events.jsonl")
    assert len(events) == 1; assert events[0]["provenance"]["source_file_id"] == "file-1"; assert events[0]["provenance"]["source_locator"] == "record[1]"; assert any(w["code"] == "MALFORMED_JSON" for w in warnings)
