from pathlib import Path

from forensickit.analysis import analyze_case, load_case
from forensickit.investigation import create_decision, create_hypothesis, create_note, update_hypothesis


def test_analyst_objects_are_separate_and_reference_checked(tmp_path: Path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "records.jsonl").write_text(
        '{"event_type":"logon","timestamp":"2026-01-01T00:00:00Z","host":"h","user":"u","session_id":"s"}\n'
        '{"event_type":"process_start","timestamp":"2026-01-01T00:00:01Z","host":"h","user":"u","session_id":"s","pid":9,"image":"x.exe"}\n',
        encoding="utf-8",
    )
    result = analyze_case(tmp_path / "case", evidence)
    event_id = result["events"][0]["event_id"]
    hypothesis = create_hypothesis(tmp_path / "case", "The session launched the observed process.", supporting=[event_id])
    updated = update_hypothesis(tmp_path / "case", hypothesis["hypothesis_id"], status="in_review", weakening=[result["events"][1]["event_id"]], analyst_note="Needs parent-process evidence.")
    note = create_note(tmp_path / "case", "Review the process lifetime source.", "event", event_id)
    decision = create_decision(tmp_path / "case", "Keep the hypothesis unresolved pending parent evidence.", evidence=[event_id])
    data = load_case(tmp_path / "case")
    assert updated["status"] == "in_review"
    assert any(item["note_id"] == note["note_id"] for item in data["notes"])
    assert any(item["decision_id"] == decision["decision_id"] for item in data["decisions"])
    assert (tmp_path / "case" / "hypotheses.json").exists()
    assert (tmp_path / "case" / "notes.json").exists()
    assert (tmp_path / "case" / "decisions.json").exists()

