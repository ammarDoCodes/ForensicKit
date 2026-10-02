import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from forensickit.graph import build_graph
from test_workbench import _request, _sample_case, _start


def test_bounded_graph_supports_entity_event_and_thread_starts(tmp_path: Path):
    case_dir, result = _sample_case(tmp_path)
    session_id = next(entity["entity_id"] for entity in result["entities"] if entity["type"] == "session")
    event_id = result["events"][0]["event_id"]
    thread_id = result["threads"][0]["thread_id"]
    entity_graph = build_graph(result, "entity", session_id, depth=1)
    assert entity_graph["start"]["id"] == session_id
    assert entity_graph["nodes"] and entity_graph["edges"]
    assert any(node["kind"] == "event" for node in entity_graph["nodes"])
    assert any(edge["observed"] for edge in entity_graph["edges"])
    assert any(edge["derived"] for edge in entity_graph["edges"])
    assert all(edge["from"] in entity_graph["node_ids"] and edge["to"] in entity_graph["node_ids"] for edge in entity_graph["edges"])
    assert any(edge["uncertain_time"] for edge in entity_graph["edges"])
    deeper = build_graph(result, "entity", session_id, depth=3)
    assert max(node["depth"] for node in entity_graph["nodes"]) <= 1
    assert max(node["depth"] for node in deeper["nodes"]) <= 3
    assert len(deeper["nodes"]) >= len(entity_graph["nodes"])
    event_graph = build_graph(result, "event", event_id, depth=1)
    assert event_graph["start"]["type"] == "event"
    thread_graph = build_graph(result, "thread", thread_id, depth=1)
    assert thread_graph["start"]["type"] == "thread"
    assert any(node["kind"] == "event" for node in thread_graph["nodes"])
    filtered = build_graph(result, "entity", session_id, depth=3, relationship_types=("parent_child_process",), confidence="moderate")
    support_edges = {"thread_contains_event", "thread_contains_entity", "gap_affects_event", "contradiction_evidence"}
    assert all(edge["edge_type"] == "parent_child_process" or edge["observed"] or edge["edge_type"] in support_edges for edge in filtered["edges"])
    assert json.dumps(entity_graph, sort_keys=True) == json.dumps(build_graph(result, "entity", session_id, depth=1), sort_keys=True)


def test_graph_api_bounds_results_and_exposes_provenance(tmp_path: Path):
    case_dir, result = _sample_case(tmp_path)
    server, thread, base_url = _start(case_dir)
    try:
        case_id = result["manifest"]["case_id"]
        entity_id = next(entity["entity_id"] for entity in result["entities"] if entity["type"] == "session")
        encoded = urllib.parse.quote(entity_id, safe="")
        status, payload = _request(base_url, f"/api/cases/{case_id}/graph?start_type=entity&start_id={encoded}&depth=1")
        assert status == 200
        assert payload["data"]["nodes"]
        assert payload["data"]["available_filters"]["relationship_types"]
        assert all("direct_evidence_ids" in node for node in payload["data"]["nodes"])
        assert all("direct_evidence_ids" in edge for edge in payload["data"]["edges"])
        status, bounded = _request(base_url, f"/api/cases/{case_id}/graph?start_type=entity&start_id={encoded}&depth=3&limit=1")
        assert status == 200
        assert bounded["data"]["result_bounds"]["nodes"]["truncated"]
        assert any(item["code"] == "GRAPH_RESULT_BOUNDED" for item in bounded["warnings"])
        try:
            _request(base_url, f"/api/cases/{case_id}/graph?start_type=event&start_id=missing-event")
        except urllib.error.HTTPError as error:
            assert error.code == 400
            missing = json.loads(error.read().decode("utf-8"))
            assert missing["error"]["code"] == "GRAPH_START_NOT_FOUND"
        else:
            raise AssertionError("missing graph start was accepted")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_graph_malformed_case_data_is_structured(tmp_path: Path):
    case_dir, result = _sample_case(tmp_path)
    normalized = case_dir / "normalized-events.jsonl"
    original = normalized.read_bytes()
    server, thread, base_url = _start(case_dir)
    try:
        normalized.write_bytes(b"{not-json\xff")
        entity_id = next(entity["entity_id"] for entity in result["entities"] if entity["type"] == "session")
        path = f"/api/cases/{result['manifest']['case_id']}/graph?start_type=entity&start_id={urllib.parse.quote(entity_id, safe='')}"
        try:
            _request(base_url, path)
        except urllib.error.HTTPError as error:
            body = json.loads(error.read().decode("utf-8"))
            assert error.code == 500
            assert body["error"]["code"] == "CASE_DATA_INVALID"
        else:
            raise AssertionError("malformed graph case data was accepted")
    finally:
        normalized.write_bytes(original)
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
