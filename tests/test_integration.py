from pathlib import Path
from forensickit.analysis import analyze_case, pivot, replay
def test_sample_case_vertical_slice(tmp_path: Path):
    evidence = tmp_path / "evidence"; evidence.mkdir(); (evidence / "events.jsonl").write_text(Path("examples/sample-case/evidence/events.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
    result = analyze_case(tmp_path / "case", evidence); assert result["events"] and result["warnings"] and result["relationships"] and result["threads"]
    relationship = next(r for r in result["relationships"] if r["type"] == "file_process_path_and_time"); assert set(relationship["evidence_ids"]).issubset({e["event_id"] for e in result["events"]})
    assert any(r["type"] == "parent_child_process" for r in result["relationships"])
    process = next(e for e in result["events"] if e["event_type"] == "process_start"); process_entity = next(x["entity_id"] for x in process["entities"] if x["entity_id"].startswith("process:")); assert process["event_id"] in pivot(tmp_path / "case", process_entity)["event_ids"]
    replayed = replay(tmp_path / "case", result["threads"][0]["thread_id"]); assert [e["event_id"] for e in replayed["events"]] == result["threads"][0]["event_ids"]
def test_repeated_analysis_is_deterministic(tmp_path: Path):
    evidence = tmp_path / "evidence"; evidence.mkdir(); (evidence / "events.jsonl").write_text(Path("examples/sample-case/evidence/events.jsonl").read_text(encoding="utf-8"), encoding="utf-8"); case = tmp_path / "case"; first = analyze_case(case, evidence); names = ["normalized-events.jsonl", "entities.json", "relationships.jsonl", "threads.json", "gaps.json", "contradictions.json", "warnings.json"]; one = {name: (case / name).read_bytes() for name in names}; second = analyze_case(case, evidence); two = {name: (case / name).read_bytes() for name in names}; assert one == two; assert first["manifest"]["case_id"] == second["manifest"]["case_id"]
