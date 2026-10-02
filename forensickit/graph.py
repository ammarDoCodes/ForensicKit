"""Deterministic, read-only evidence graph projection for the workbench."""

from __future__ import annotations

from collections import defaultdict, deque
from copy import deepcopy

from .constants import SCHEMA_VERSION


GRAPH_DEFAULT_LIMIT = 1000
GRAPH_MAX_LIMIT = 2000
GRAPH_MAX_DEPTH = 3
GRAPH_DERIVATION = {"algorithm": "workbench-evidence-graph", "version": "1.0.0"}


class GraphError(ValueError):
    """A safe, structured graph request or case-data error."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _node_id(kind: str, object_id: str) -> str:
    return f"{kind}:{object_id}"


def _sorted_strings(values) -> list[str]:
    return sorted({str(value) for value in values if value is not None})


def _event_uncertain(event: dict) -> bool:
    return event.get("observed_at", {}).get("quality") != "exact"


def _edge(
    edge_id: str,
    edge_type: str,
    from_id: str,
    to_id: str,
    label: str,
    confidence: str,
    observed: bool,
    derived: bool,
    evidence_ids=None,
    provenance=None,
    derivation=None,
    thread_ids=None,
    uncertain=False,
    explanation=None,
    relationship_id=None,
) -> dict:
    result = {
        "schema_version": SCHEMA_VERSION,
        "edge_id": edge_id,
        "edge_type": edge_type,
        "from": from_id,
        "to": to_id,
        "label": label,
        "confidence": confidence or "unknown",
        "observed": bool(observed),
        "derived": bool(derived),
        "evidence_ids": _sorted_strings(evidence_ids or []),
        "direct_evidence_ids": _sorted_strings(evidence_ids or []),
        "thread_ids": _sorted_strings(thread_ids or []),
        "uncertain_time": bool(uncertain),
    }
    if provenance:
        result["provenance"] = deepcopy(provenance)
    if derivation:
        result["derivation"] = deepcopy(derivation)
    if explanation:
        result["explanation"] = str(explanation)
    if relationship_id:
        result["relationship_id"] = relationship_id
    return result


def _entity_node(entity: dict, depth: int) -> dict:
    entity_id = entity.get("entity_id")
    return {
        "schema_version": SCHEMA_VERSION,
        "node_id": _node_id("entity", entity_id),
        "kind": "entity",
        "node_type": entity.get("type", "unknown"),
        "entity_type": entity.get("type", "unknown"),
        "object_id": entity_id,
        "label": entity.get("display_name") or entity_id,
        "display_name": entity.get("display_name") or entity_id,
        "depth": depth,
        "observed": True,
        "derived": False,
        "confidence": "unknown",
        "uncertain_time": False,
        "evidence_ids": _sorted_strings(entity.get("event_ids", [])),
        "direct_evidence_ids": _sorted_strings(entity.get("event_ids", [])),
        "provenance": deepcopy(entity.get("provenance", {})),
    }


def _event_node(event: dict, depth: int) -> dict:
    event_id = event.get("event_id")
    uncertain = _event_uncertain(event)
    return {
        "schema_version": SCHEMA_VERSION,
        "node_id": _node_id("event", event_id),
        "kind": "event",
        "node_type": "event",
        "object_id": event_id,
        "label": event.get("event_type") or event_id,
        "display_name": event.get("event_type") or event_id,
        "depth": depth,
        "observed": True,
        "derived": False,
        "confidence": "unknown",
        "uncertain_time": uncertain,
        "event_type": event.get("event_type"),
        "observed_at": deepcopy(event.get("observed_at", {})),
        "evidence_ids": [event_id] if event_id else [],
        "direct_evidence_ids": [event_id] if event_id else [],
        "provenance": deepcopy(event.get("provenance", {})),
    }


def _thread_node(thread: dict, depth: int) -> dict:
    thread_id = thread.get("thread_id")
    evidence = thread.get("supporting_evidence_ids", thread.get("event_ids", []))
    return {
        "schema_version": SCHEMA_VERSION,
        "node_id": _node_id("thread", thread_id),
        "kind": "thread",
        "node_type": "thread",
        "object_id": thread_id,
        "label": thread.get("title") or thread_id,
        "display_name": thread.get("title") or thread_id,
        "depth": depth,
        "observed": False,
        "derived": True,
        "confidence": thread.get("confidence", "unknown"),
        "uncertain_time": False,
        "status": thread.get("status"),
        "evidence_ids": _sorted_strings(evidence),
        "direct_evidence_ids": _sorted_strings(evidence),
        "provenance": {"derivation": deepcopy(thread.get("derivation", {}))},
        "derivation": deepcopy(thread.get("derivation", {})),
    }


def _issue_node(issue: dict, kind: str, depth: int) -> dict:
    object_id = issue.get(f"{kind}_id")
    evidence = issue.get("evidence_ids", [])
    derivation = issue.get("derivation", {})
    return {
        "schema_version": SCHEMA_VERSION,
        "node_id": _node_id(kind, object_id),
        "kind": kind,
        "node_type": kind,
        "object_id": object_id,
        "label": issue.get("description") or issue.get("type") or object_id,
        "display_name": issue.get("description") or issue.get("type") or object_id,
        "depth": depth,
        "observed": False,
        "derived": True,
        "confidence": issue.get("impact", "unknown") if kind == "gap" else "unknown",
        "uncertain_time": False,
        "status": issue.get("resolution_status") if kind == "contradiction" else issue.get("reason"),
        "issue_type": issue.get("type"),
        "evidence_ids": _sorted_strings(evidence),
        "direct_evidence_ids": _sorted_strings(evidence),
        "provenance": {"derivation": deepcopy(derivation), "evidence_ids": _sorted_strings(evidence)},
        "derivation": deepcopy(derivation),
    }


def _parse_depth(depth) -> int:
    try:
        value = int(depth)
    except (TypeError, ValueError) as exc:
        raise GraphError("GRAPH_DEPTH_INVALID", "Graph depth must be an integer from 0 to 3.") from exc
    if value < 0 or value > GRAPH_MAX_DEPTH:
        raise GraphError("GRAPH_DEPTH_INVALID", "Graph depth must be an integer from 0 to 3.")
    return value


def _parse_limit(limit) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError) as exc:
        raise GraphError("GRAPH_LIMIT_INVALID", "Graph limit must be a positive integer.") from exc
    if value <= 0:
        raise GraphError("GRAPH_LIMIT_INVALID", "Graph limit must be a positive integer.")
    return min(value, GRAPH_MAX_LIMIT)


def _filter_values(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        values = value.split(",")
    else:
        values = value
    return tuple(sorted({str(item).strip() for item in values if str(item).strip()}))


def _validate_start(data: dict, start_type: str, start_id: str) -> tuple[str, str]:
    start_type = str(start_type or "").casefold()
    if start_type not in {"entity", "event", "thread"} or not isinstance(start_id, str) or not start_id:
        raise GraphError("GRAPH_START_INVALID", "Graph start_type must be entity, event, or thread with a non-empty start_id.")
    key = {"entity": "entities", "event": "events", "thread": "threads"}[start_type]
    object_key = {"entity": "entity_id", "event": "event_id", "thread": "thread_id"}[start_type]
    if not any(item.get(object_key) == start_id for item in data.get(key, [])):
        raise GraphError("GRAPH_START_NOT_FOUND", f"The requested graph {start_type} was not found.")
    return start_type, start_id


def build_graph(
    data: dict,
    start_type: str,
    start_id: str,
    depth=1,
    limit=GRAPH_DEFAULT_LIMIT,
    relationship_types=(),
    confidence=None,
    entity_type=None,
    thread_id=None,
) -> dict:
    """Build a stable graph projection without changing the supplied case data."""

    depth = _parse_depth(depth)
    limit = _parse_limit(limit)
    start_type, start_id = _validate_start(data, start_type, start_id)
    relationship_types = _filter_values(relationship_types)
    confidence = str(confidence or "").strip().casefold()
    entity_type = str(entity_type or "").strip().casefold()
    thread_id = str(thread_id or "").strip()

    entities = {item.get("entity_id"): item for item in data.get("entities", []) if item.get("entity_id") and item.get("type") != "source"}
    events = {item.get("event_id"): item for item in data.get("events", []) if item.get("event_id")}
    threads = {item.get("thread_id"): item for item in data.get("threads", []) if item.get("thread_id")}
    gaps = {item.get("gap_id"): item for item in data.get("gaps", []) if item.get("gap_id")}
    contradictions = {item.get("contradiction_id"): item for item in data.get("contradictions", []) if item.get("contradiction_id")}
    relationships = {item.get("relationship_id"): item for item in data.get("relationships", []) if item.get("relationship_id")}
    if thread_id and thread_id not in threads:
        raise GraphError("GRAPH_THREAD_NOT_FOUND", "The requested graph thread filter was not found.")

    nodes = {}
    for entity in entities.values():
        nodes[_node_id("entity", entity["entity_id"])] = _entity_node(entity, 0)
    for event in events.values():
        nodes[_node_id("event", event["event_id"])] = _event_node(event, 0)
    for thread in threads.values():
        nodes[_node_id("thread", thread["thread_id"])] = _thread_node(thread, 0)
    for gap in gaps.values():
        nodes[_node_id("gap", gap["gap_id"])] = _issue_node(gap, "gap", 0)
    for contradiction in contradictions.values():
        nodes[_node_id("contradiction", contradiction["contradiction_id"])] = _issue_node(contradiction, "contradiction", 0)

    event_thread_ids = defaultdict(set)
    entity_thread_ids = defaultdict(set)
    relationship_thread_ids = defaultdict(set)
    gap_thread_ids = defaultdict(set)
    contradiction_thread_ids = defaultdict(set)
    for thread in threads.values():
        current = thread["thread_id"]
        for event_id in thread.get("event_ids", []):
            event_thread_ids[event_id].add(current)
        for entity_id in thread.get("entity_ids", []):
            entity_thread_ids[entity_id].add(current)
        for relationship_id in thread.get("relationship_ids", []):
            relationship_thread_ids[relationship_id].add(current)
        for gap_id in thread.get("gap_ids", []):
            gap_thread_ids[gap_id].add(current)
        for contradiction_id in thread.get("contradiction_ids", []):
            contradiction_thread_ids[contradiction_id].add(current)

    edges = {}
    for event in events.values():
        event_id = event["event_id"]
        for reference in event.get("entities", []):
            entity_id = reference.get("entity_id") if isinstance(reference, dict) else None
            if entity_id not in entities:
                continue
            edge_id = f"observed:{event_id}:{entity_id}:{reference.get('role', 'related')}"
            edges[edge_id] = _edge(
                edge_id,
                "observed_event_entity",
                _node_id("event", event_id),
                _node_id("entity", entity_id),
                f"observed · {reference.get('role', 'related')}",
                "unknown",
                True,
                False,
                [event_id],
                event.get("provenance"),
                thread_ids=event_thread_ids.get(event_id),
                uncertain=_event_uncertain(event),
            )

    for relationship in relationships.values():
        from_id, to_id = relationship.get("from"), relationship.get("to")
        if from_id not in entities or to_id not in entities:
            raise GraphError("GRAPH_DATA_INVALID", f"Relationship {relationship.get('relationship_id')} references an unavailable entity.")
        relationship_id = relationship["relationship_id"]
        relationship_strength = str(relationship.get("strength") or "unknown")
        if relationship_types and relationship.get("type") not in relationship_types:
            continue
        if confidence and relationship_strength.casefold() != confidence:
            continue
        if thread_id and thread_id not in relationship_thread_ids.get(relationship_id, set()):
            continue
        evidence_events = [events[event_id] for event_id in relationship.get("evidence_ids", []) if event_id in events]
        uncertain = relationship.get("time_distance_seconds") is None or any(_event_uncertain(event) for event in evidence_events)
        edges[f"relationship:{relationship_id}"] = _edge(
            f"relationship:{relationship_id}",
            relationship.get("type", "relationship"),
            _node_id("entity", from_id),
            _node_id("entity", to_id),
            f"{relationship.get('type', 'relationship')} · {relationship_strength}",
            relationship_strength,
            False,
            True,
            relationship.get("evidence_ids", []),
            {"relationship_id": relationship_id, "evidence_ids": _sorted_strings(relationship.get("evidence_ids", []))},
            {"rule_id": relationship.get("rule_id"), "rule_version": relationship.get("rule_version")},
            relationship_thread_ids.get(relationship_id),
            uncertain,
            relationship.get("explanation"),
            relationship_id,
        )

    for thread in threads.values():
        current = thread["thread_id"]
        if thread_id and current != thread_id:
            continue
        for event_id in thread.get("event_ids", []):
            if event_id not in events:
                raise GraphError("GRAPH_DATA_INVALID", f"Thread {current} references an unavailable event.")
            edge_id = f"thread-event:{current}:{event_id}"
            edges[edge_id] = _edge(edge_id, "thread_contains_event", _node_id("thread", current), _node_id("event", event_id), "thread membership", thread.get("confidence", "unknown"), False, True, thread.get("supporting_evidence_ids", []), derivation=thread.get("derivation") or GRAPH_DERIVATION, thread_ids=[current], uncertain=False)
        for entity_id in thread.get("entity_ids", []):
            if entity_id not in entities:
                continue
            edge_id = f"thread-entity:{current}:{entity_id}"
            edges[edge_id] = _edge(edge_id, "thread_contains_entity", _node_id("thread", current), _node_id("entity", entity_id), "thread membership", thread.get("confidence", "unknown"), False, True, thread.get("supporting_evidence_ids", []), derivation=thread.get("derivation") or GRAPH_DERIVATION, thread_ids=[current], uncertain=False)

    for gap in gaps.values():
        gap_id = gap["gap_id"]
        if thread_id and thread_id not in gap_thread_ids.get(gap_id, set()):
            continue
        for event_id in gap.get("affected_event_ids", []):
            if event_id not in events:
                continue
            edge_id = f"gap-event:{gap_id}:{event_id}"
            edges[edge_id] = _edge(edge_id, "gap_affects_event", _node_id("gap", gap_id), _node_id("event", event_id), "evidence gap", gap.get("impact", "unknown"), False, True, gap.get("evidence_ids", []), derivation=gap.get("derivation") or GRAPH_DERIVATION, thread_ids=gap_thread_ids.get(gap_id), uncertain=_event_uncertain(events[event_id]), explanation=gap.get("description"))

    for contradiction in contradictions.values():
        contradiction_id = contradiction["contradiction_id"]
        if thread_id and thread_id not in contradiction_thread_ids.get(contradiction_id, set()):
            continue
        for event_id in contradiction.get("evidence_ids", []):
            if event_id not in events:
                continue
            edge_id = f"contradiction-event:{contradiction_id}:{event_id}"
            edges[edge_id] = _edge(edge_id, "contradiction_evidence", _node_id("contradiction", contradiction_id), _node_id("event", event_id), "contradiction evidence", "unknown", False, True, contradiction.get("evidence_ids", []), derivation=contradiction.get("derivation") or GRAPH_DERIVATION, thread_ids=contradiction_thread_ids.get(contradiction_id), uncertain=_event_uncertain(events[event_id]), explanation=contradiction.get("description"))
        for relationship_id in contradiction.get("affected_relationship_ids", []):
            relationship = relationships.get(relationship_id)
            if not relationship:
                continue
            for endpoint in (relationship.get("from"), relationship.get("to")):
                if endpoint not in entities:
                    continue
                edge_id = f"contradiction-relationship:{contradiction_id}:{relationship_id}:{endpoint}"
                edges[edge_id] = _edge(edge_id, "contradiction_relationship", _node_id("contradiction", contradiction_id), _node_id("entity", endpoint), "contradiction relationship", "unknown", False, True, contradiction.get("evidence_ids", []) or relationship.get("evidence_ids", []), derivation=contradiction.get("derivation") or GRAPH_DERIVATION, thread_ids=contradiction_thread_ids.get(contradiction_id), uncertain=True, explanation=contradiction.get("description"))

    start_node_id = _node_id(start_type, start_id)
    if start_node_id not in nodes:
        raise GraphError("GRAPH_DATA_INVALID", "The graph start object could not be represented safely.")

    if entity_type:
        for node_id, node in list(nodes.items()):
            if node.get("kind") == "entity" and node.get("entity_type", "").casefold() != entity_type and node_id != start_node_id:
                nodes.pop(node_id)
    filtered_edges = {edge_id: edge for edge_id, edge in edges.items() if edge["from"] in nodes and edge["to"] in nodes}
    if thread_id:
        filtered_edges = {edge_id: edge for edge_id, edge in filtered_edges.items() if thread_id in edge.get("thread_ids", set())}

    adjacency = defaultdict(list)
    for edge in filtered_edges.values():
        adjacency[edge["from"]].append((edge["to"], edge["edge_id"]))
        adjacency[edge["to"]].append((edge["from"], edge["edge_id"]))
    distances = {start_node_id: 0}
    queue = deque([start_node_id])
    while queue:
        current = queue.popleft()
        if distances[current] >= depth:
            continue
        for neighbor, _ in sorted(adjacency[current], key=lambda item: (item[0], item[1])):
            if neighbor not in distances:
                distances[neighbor] = distances[current] + 1
                queue.append(neighbor)

    reachable_nodes = {node_id: deepcopy(nodes[node_id]) for node_id in distances}
    for node_id, node in reachable_nodes.items():
        node["depth"] = distances[node_id]
    reachable_edges = {edge_id: deepcopy(edge) for edge_id, edge in filtered_edges.items() if edge["from"] in reachable_nodes and edge["to"] in reachable_nodes}
    ordered_node_ids = sorted(reachable_nodes, key=lambda node_id: (0 if node_id == start_node_id else 1, distances[node_id], node_id))
    ordered_edge_ids = sorted(reachable_edges)
    selected_node_ids = ordered_node_ids[:limit]
    selected_node_set = set(selected_node_ids)
    selected_edge_ids = [edge_id for edge_id in ordered_edge_ids if reachable_edges[edge_id]["from"] in selected_node_set and reachable_edges[edge_id]["to"] in selected_node_set][:limit]

    result_bounds = {
        "nodes": {"total": len(ordered_node_ids), "returned": len(selected_node_ids), "limit": limit, "truncated": len(selected_node_ids) < len(ordered_node_ids)},
        "edges": {"total": len(ordered_edge_ids), "returned": len(selected_edge_ids), "limit": limit, "truncated": len(selected_edge_ids) < len(ordered_edge_ids)},
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "start": {"type": start_type, "id": start_id, "node_id": start_node_id},
        "depth": depth,
        "nodes": [reachable_nodes[node_id] for node_id in selected_node_ids],
        "edges": [reachable_edges[edge_id] for edge_id in selected_edge_ids],
        "node_ids": selected_node_ids,
        "edge_ids": selected_edge_ids,
        "result_bounds": result_bounds,
        "available_filters": {
            "relationship_types": sorted({relationship.get("type") for relationship in relationships.values() if relationship.get("type")}),
            "confidence": sorted({"unknown", *[str(relationship.get("strength") or "unknown") for relationship in relationships.values()]}),
            "entity_types": sorted({entity.get("type") for entity in entities.values() if entity.get("type")}),
            "thread_ids": sorted(threads),
        },
    }
