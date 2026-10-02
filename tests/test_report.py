import json
from pathlib import Path

from forensickit.analysis import analyze_case
from forensickit.cli import main as cli_main
from forensickit.investigation import create_decision, create_hypothesis, create_note
from forensickit.report import EVTX_VALIDATION_STATUS, build_report, export_report, load_redaction_config, render_html, render_json


ROOT = Path(__file__).resolve().parent.parent


def _sample_case(tmp_path: Path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    source = ROOT / "examples" / "sample-case" / "evidence" / "events.jsonl"
    target = evidence / "events.jsonl"
    target.write_bytes(source.read_bytes())
    case_dir = tmp_path / "case"
    result = analyze_case(case_dir, evidence)
    return case_dir, target, result


def test_report_is_deterministic_provenance_preserving_and_raw_free(tmp_path: Path):
    case_dir, source, result = _sample_case(tmp_path)
    first = build_report(case_dir)
    second = build_report(case_dir)
    assert render_json(first) == render_json(second)
    second_case = tmp_path / "case-second"
    analyze_case(second_case, tmp_path / "evidence")
    assert render_json(first) == render_json(build_report(second_case))
    assert first["case"]["manifest_hash"].startswith("sha256:")
    assert first["case"]["source_file_hashes"]
    assert first["evtx_validation_status"] == EVTX_VALIDATION_STATUS
    assert first["events"]
    assert all("source_payload" not in event for event in first["events"])
    assert all(item["report_provenance"]["direct_evidence_ids"] for item in first["relationships"])
    assert all(item["report_provenance"]["derivation"] for item in first["relationships"])
    assert first["evidence_gaps"]
    assert source.read_bytes() == (ROOT / "examples" / "sample-case" / "evidence" / "events.jsonl").read_bytes()


def test_report_scopes_graph_and_investigation_objects(tmp_path: Path):
    case_dir, _, result = _sample_case(tmp_path)
    event_id = result["events"][0]["event_id"]
    gap_id = result["gaps"][0]["gap_id"]
    thread_id = result["threads"][0]["thread_id"]
    entity_id = next(entity["entity_id"] for entity in result["entities"] if entity["type"] == "session")
    hypothesis = create_hypothesis(case_dir, "Review the selected thread.", [event_id], [], [gap_id])
    note = create_note(case_dir, "Analyst-authored review note.", "thread", thread_id)
    decision = create_decision(case_dir, "Keep attribution unresolved.", evidence=[event_id])

    thread_report = build_report(case_dir, scope="thread", scope_id=thread_id)
    assert thread_report["scope"] == {"type": "thread", "id": thread_id}
    assert thread_report["threads"][0]["thread_id"] == thread_id
    assert thread_report["threads"][0]["time_range"]["start_utc"]

    hypothesis_report = build_report(case_dir, scope="hypothesis", scope_id=hypothesis["hypothesis_id"])
    assert hypothesis_report["investigation"]["hypotheses"][0]["hypothesis_id"] == hypothesis["hypothesis_id"]
    assert all(item["authorship"] == "analyst-authored" for item in hypothesis_report["investigation"]["notes"])

    graph_report = build_report(case_dir, graph_start_type="entity", graph_start_id=entity_id, graph_depth=1, graph_limit=1)
    assert graph_report["graph"]["selected"]
    assert graph_report["graph"]["summary"]["result_bounds"]
    assert graph_report["graph"]["data"]["nodes"]

    investigation_report = build_report(case_dir, scope="investigation")
    assert any(item["note_id"] == note["note_id"] and item["authorship"] == "analyst-authored" for item in investigation_report["investigation"]["notes"])
    assert any(item["decision_id"] == decision["decision_id"] for item in investigation_report["investigation"]["decisions"])
    assert investigation_report["investigation"]["notes"][0]["source_evidence"] is False


def test_report_redaction_html_security_and_source_protection(tmp_path: Path):
    case_dir, source, result = _sample_case(tmp_path)
    config_path = tmp_path / "redaction.json"
    config_path.write_text(json.dumps({"categories": ["user", "path", "command_line", "ip", "domain", "text"]}), encoding="utf-8")
    assert "user" in load_redaction_config(config_path)
    report = build_report(case_dir, redaction_config=config_path)
    assert report["redaction"]["raw_evidence_included"] is False
    assert "[REDACTED:user]" in json.dumps(report)
    assert "[REDACTED:path]" in json.dumps(report)
    note = create_note(case_dir, "<script>alert('untrusted')</script>", "event", result["events"][0]["event_id"])
    report = build_report(case_dir)
    page = render_html(report)
    assert "<script>alert" not in page
    assert "&lt;script&gt;" in page
    with_source_path = source
    try:
        export_report(report, with_source_path, "json")
    except ValueError as error:
        assert "source evidence" in str(error)
    else:
        raise AssertionError("export overwrote source evidence")
    assert source.read_bytes() == (ROOT / "examples/sample-case/evidence/events.jsonl").read_bytes()


def test_report_cli_writes_json_html_and_markdown(tmp_path: Path):
    case_dir, _, _ = _sample_case(tmp_path)
    json_path = tmp_path / "reports" / "review.json"
    html_path = tmp_path / "reports" / "review.html"
    markdown_path = tmp_path / "reports" / "review.md"
    assert cli_main(["export", str(case_dir), "--format", "json", "--output", str(json_path)]) == 0
    assert cli_main(["export", str(case_dir), "--format", "html", "--output", str(html_path)]) == 0
    assert cli_main(["export", str(case_dir), "--format", "markdown", "--output", str(markdown_path)]) == 0
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["report_schema_version"] == "1.0"
    assert "default-src 'none'" in html_path.read_text(encoding="utf-8")
    assert markdown_path.read_text(encoding="utf-8").startswith("# ForensicKit Investigation Report")
