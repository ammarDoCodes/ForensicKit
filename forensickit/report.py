"""Deterministic, offline investigation report export.

Reports are a presentation/export projection. They do not re-run parsing or
correlation, and they never write to source evidence. Raw source payloads are
omitted unless a future, explicitly reviewed export contract adds them.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

from .analysis import load_case
from .constants import RULE_VERSION, SCHEMA_VERSION
from .graph import GraphError, build_graph
from .timeutil import timestamp_sort_key
from .util import sha256_bytes, sha256_text, stable_id, stable_json


REPORT_SCHEMA_VERSION = "1.0"
REPORT_VERSION = "1.0.0"
REPORT_DERIVATION = {"algorithm": "investigation-report-export", "version": REPORT_VERSION}
EVTX_VALIDATION_STATUS = "EVTX PARTIALLY VALIDATED — pending approved Windows Security and PowerShell binary fixtures"
DEFAULT_REDACTIONS = frozenset({"path"})
REDACTION_CATEGORIES = frozenset({"user", "path", "command_line", "ip", "domain", "host", "device", "text"})
REDACTION_MARKER = "[REDACTED:{category}]"


def _manifest_hash(manifest: dict) -> str:
    canonical = dict(manifest)
    canonical.pop("created_at_utc", None)
    return "sha256:" + sha256_text(stable_json(canonical))


def _read_config(case_dir: Path) -> tuple[dict, list[dict]]:
    path = case_dir / "analysis-config.json"
    if not path.exists():
        return {}, [{"schema_version": SCHEMA_VERSION, "severity": "warning", "code": "REPORT_CONFIG_MISSING", "message": "Analysis configuration is missing from the selected case."}]
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}, [{"schema_version": SCHEMA_VERSION, "severity": "warning", "code": "REPORT_CONFIG_INVALID", "message": "Analysis configuration could not be read safely."}]
    if not isinstance(value, dict):
        return {}, [{"schema_version": SCHEMA_VERSION, "severity": "warning", "code": "REPORT_CONFIG_INVALID", "message": "Analysis configuration is not a JSON object."}]
    return value, []


def _normalise_categories(categories: Iterable[str] | None) -> set[str]:
    result = set(DEFAULT_REDACTIONS)
    for value in categories or ():
        for category in str(value).split(","):
            category = category.strip().casefold().replace("-", "_")
            if not category:
                continue
            if category not in REDACTION_CATEGORIES:
                raise ValueError(f"unsupported redaction category: {category}")
            result.add(category)
    return result


def load_redaction_config(path: Path | None) -> set[str]:
    """Load a small, offline redaction configuration.

    The configuration is intentionally limited to named categories. It cannot
    supply executable code or arbitrary transformation expressions.
    """

    if path is None:
        return set(DEFAULT_REDACTIONS)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"redaction configuration could not be read: {exc}") from exc
    if isinstance(value, list):
        categories = value
    elif isinstance(value, dict):
        categories = value.get("categories", [])
    else:
        raise ValueError("redaction configuration must be a JSON list or object")
    if not isinstance(categories, list) or not all(isinstance(item, str) for item in categories):
        raise ValueError("redaction configuration categories must be a list of strings")
    return _normalise_categories(categories)


def _key_category(key: str) -> str | None:
    normalized = key.casefold().replace("-", "_")
    if normalized in {"user", "username", "user_name", "account", "principal", "owner"}:
        return "user"
    if normalized in {"command", "command_line", "commandline", "script_block", "scriptblock", "arguments"} or "command_line" in normalized:
        return "command_line"
    if normalized in {"remote_ip", "local_ip", "source_ip", "destination_ip", "ip", "ip_address", "address"} or normalized.endswith("_ip"):
        return "ip"
    if "domain" in normalized:
        return "domain"
    if normalized in {"host", "hostname", "host_name"}:
        return "host"
    if "device" in normalized or normalized in {"volume_serial", "serial_number"}:
        return "device"
    if "path" in normalized or normalized in {"filename", "file_name", "source_file", "target_file"}:
        return "path"
    if normalized in {"text", "statement", "rationale", "analyst_note"}:
        return "text"
    return None


def _marker(category: str) -> str:
    return REDACTION_MARKER.format(category=category)


def _sanitize(value: Any, categories: set[str], context: str | None = None) -> Any:
    if context and context in categories and value is not None:
        return _marker(context)
    if isinstance(value, dict):
        result = {}
        for key in sorted(value):
            if key == "source_payload":
                continue
            category = _key_category(str(key))
            result[key] = _sanitize(value[key], categories, category)
        return result
    if isinstance(value, list):
        return [_sanitize(item, categories, context) for item in value]
    if isinstance(value, tuple):
        return [_sanitize(item, categories, context) for item in value]
    return value


def _public_input(item: dict) -> dict:
    # Relative paths are intentionally omitted. File IDs and hashes remain
    # available for provenance without exposing a host filesystem layout.
    return {
        "file_id": item.get("file_id"),
        "sha256": item.get("sha256"),
        "size_bytes": item.get("size_bytes"),
        "detected_format": item.get("detected_format"),
        "parser": item.get("parser"),
        "parser_version": item.get("parser_version"),
    }


def _sort_events(events: list[dict]) -> list[dict]:
    return sorted(events, key=lambda event: (timestamp_sort_key(event.get("observed_at", {})), event.get("event_id", "")))


def _time_range(events: list[dict]) -> dict:
    ordered = _sort_events(events)
    if not ordered:
        return {"start_utc": None, "end_utc": None, "start_original": None, "end_original": None, "uncertain": False}
    first, last = ordered[0], ordered[-1]
    return {
        "start_utc": first.get("observed_at", {}).get("utc"),
        "end_utc": last.get("observed_at", {}).get("utc"),
        "start_original": first.get("observed_at", {}).get("original"),
        "end_original": last.get("observed_at", {}).get("original"),
        "uncertain": any(event.get("observed_at", {}).get("quality") != "exact" for event in ordered),
    }


def _time_summary(events: list[dict]) -> dict:
    qualities = Counter((event.get("observed_at", {}).get("quality") or "missing") for event in events)
    precisions = Counter((event.get("observed_at", {}).get("precision") or "missing") for event in events)
    timezone_sources = Counter((event.get("observed_at", {}).get("timezone_source") or "missing") for event in events)
    return {
        "coverage": _time_range(events),
        "event_count": len(events),
        "quality_counts": dict(sorted(qualities.items())),
        "precision_counts": dict(sorted(precisions.items())),
        "timezone_source_counts": dict(sorted(timezone_sources.items())),
        "uncertain_event_ids": sorted(event.get("event_id") for event in events if event.get("observed_at", {}).get("quality") != "exact"),
    }


def _valid_ids(data: dict) -> dict[str, set[str]]:
    return {
        "events": {item.get("event_id") for item in data.get("events", [])},
        "entities": {item.get("entity_id") for item in data.get("entities", [])},
        "relationships": {item.get("relationship_id") for item in data.get("relationships", [])},
        "threads": {item.get("thread_id") for item in data.get("threads", [])},
        "gaps": {item.get("gap_id") for item in data.get("gaps", [])},
        "contradictions": {item.get("contradiction_id") for item in data.get("contradictions", [])},
        "hypotheses": {item.get("hypothesis_id") for item in data.get("hypotheses", [])},
        "notes": {item.get("note_id") for item in data.get("notes", [])},
        "decisions": {item.get("decision_id") for item in data.get("decisions", [])},
    }


def _select_scope(data: dict, scope: str, scope_id: str | None) -> dict[str, set[str]]:
    ids = _valid_ids(data)
    if scope not in {"case", "investigation", "thread", "hypothesis"}:
        raise ValueError("report scope must be case, investigation, thread, or hypothesis")
    if scope in {"case", "investigation"}:
        return {key: set(value) for key, value in ids.items()}
    if not scope_id:
        raise ValueError(f"{scope} scope requires an ID")
    selected = {key: set() for key in ids}
    if scope == "thread":
        thread = next((item for item in data.get("threads", []) if item.get("thread_id") == scope_id), None)
        if thread is None:
            raise ValueError(f"thread not found: {scope_id}")
        selected["threads"].add(scope_id)
        selected["events"].update(thread.get("event_ids", []))
        selected["entities"].update(thread.get("entity_ids", []))
        selected["relationships"].update(thread.get("relationship_ids", []))
        selected["gaps"].update(thread.get("gap_ids", []))
        selected["contradictions"].update(thread.get("contradiction_ids", []))
    else:
        hypothesis = next((item for item in data.get("hypotheses", []) if item.get("hypothesis_id") == scope_id), None)
        if hypothesis is None:
            raise ValueError(f"hypothesis not found: {scope_id}")
        selected["hypotheses"].add(scope_id)
        references = set(hypothesis.get("supporting_evidence_ids", [])) | set(hypothesis.get("weakening_evidence_ids", [])) | set(hypothesis.get("unresolved_gap_ids", []))
        selected["events"].update(references & ids["events"])
        selected["relationships"].update(references & ids["relationships"])
        selected["gaps"].update(references & ids["gaps"])
        selected["contradictions"].update(references & ids["contradictions"])

    relationships = {item.get("relationship_id"): item for item in data.get("relationships", [])}
    gaps = {item.get("gap_id"): item for item in data.get("gaps", [])}
    contradictions = {item.get("contradiction_id"): item for item in data.get("contradictions", [])}
    selected["events"].update(event_id for relationship_id in selected["relationships"] for event_id in relationships.get(relationship_id, {}).get("evidence_ids", []))
    selected["events"].update(event_id for gap_id in selected["gaps"] for event_id in set(gaps.get(gap_id, {}).get("evidence_ids", [])) | set(gaps.get(gap_id, {}).get("affected_event_ids", [])))
    selected["events"].update(event_id for contradiction_id in selected["contradictions"] for event_id in contradictions.get(contradiction_id, {}).get("evidence_ids", []))
    selected["relationships"].update(relationship_id for contradiction_id in selected["contradictions"] for relationship_id in contradictions.get(contradiction_id, {}).get("affected_relationship_ids", []))

    event_ids = selected["events"]
    selected["relationships"].update(item.get("relationship_id") for item in data.get("relationships", []) if set(item.get("evidence_ids", [])) & event_ids)
    selected["gaps"].update(item.get("gap_id") for item in data.get("gaps", []) if set(item.get("evidence_ids", [])) & event_ids or set(item.get("affected_event_ids", [])) & event_ids)
    selected["contradictions"].update(item.get("contradiction_id") for item in data.get("contradictions", []) if set(item.get("evidence_ids", [])) & event_ids)
    selected["entities"].update(entity.get("entity_id") for event in data.get("events", []) if event.get("event_id") in event_ids for entity in event.get("entities", []))
    selected["entities"].update(endpoint for relationship_id in selected["relationships"] for endpoint in (relationships.get(relationship_id, {}).get("from"), relationships.get(relationship_id, {}).get("to")) if endpoint)
    selected["threads"].update(thread.get("thread_id") for thread in data.get("threads", []) if set(thread.get("event_ids", [])) & event_ids or set(thread.get("relationship_ids", [])) & selected["relationships"] or set(thread.get("gap_ids", [])) & selected["gaps"] or set(thread.get("contradiction_ids", [])) & selected["contradictions"])
    selected["hypotheses"].update(hypothesis.get("hypothesis_id") for hypothesis in data.get("hypotheses", []) if set(hypothesis.get("supporting_evidence_ids", [])) & (event_ids | selected["relationships"] | selected["gaps"] | selected["contradictions"]) or set(hypothesis.get("weakening_evidence_ids", [])) & (event_ids | selected["relationships"] | selected["gaps"] | selected["contradictions"]))
    return {key: {item for item in value if item is not None and item in ids[key]} for key, value in selected.items()}


def _analyst_selection(data: dict, selected: dict[str, set[str]]) -> tuple[set[str], set[str]]:
    references = selected["events"] | selected["relationships"] | selected["gaps"] | selected["contradictions"] | selected["threads"] | selected["hypotheses"]
    note_ids = {item.get("note_id") for item in data.get("notes", []) if not item.get("target_id") or item.get("target_id") in references}
    decision_ids = {item.get("decision_id") for item in data.get("decisions", []) if not item.get("evidence_ids") or set(item.get("evidence_ids", [])) & references}
    return note_ids, decision_ids


def _report_provenance(kind: str, direct_ids: Iterable[str], derivation: dict | None = None, source: dict | None = None) -> dict:
    result = {"claim_type": kind, "direct_evidence_ids": sorted({value for value in direct_ids if value})}
    if source is not None:
        result["source_provenance"] = deepcopy(source)
    if derivation:
        result["derivation"] = deepcopy(derivation)
    return result


def _entity_category(entity: dict) -> str | None:
    return {"user": "user", "host": "host", "file": "path", "device": "device", "ip": "ip", "domain": "domain"}.get(entity.get("type"))


def _entity_aliases(data: dict, categories: set[str]) -> dict[str, str]:
    aliases = {}
    for entity in data.get("entities", []):
        entity_id = entity.get("entity_id")
        category = _entity_category(entity)
        if entity_id and category in categories:
            aliases[entity_id] = stable_id("entity-redacted", category, entity_id, length=16)
    return aliases


def _alias_entity(value: Any, aliases: dict[str, str]) -> Any:
    if isinstance(value, str):
        return aliases.get(value, value)
    return value


def _replace_entity_tokens(value: Any, aliases: dict[str, str]) -> Any:
    if not isinstance(value, str):
        return value
    result = value
    for original, alias in sorted(aliases.items(), key=lambda item: len(item[0]), reverse=True):
        result = result.replace(original, alias)
    return result


def _event_confidence(event_id: str, relationships: list[dict]) -> str:
    rank = {"unknown": 0, "weak": 1, "moderate": 2, "high": 3}
    value = "unknown"
    for relationship in relationships:
        if event_id in relationship.get("evidence_ids", []) and rank.get(str(relationship.get("strength", "unknown")), 0) > rank[value]:
            value = str(relationship.get("strength", "unknown"))
    return value


def _enrich(data: dict, selected: dict[str, set[str]], categories: set[str], aliases: dict[str, str]) -> dict:
    events_by_id = {item.get("event_id"): item for item in data.get("events", [])}
    relationships_by_id = {item.get("relationship_id"): item for item in data.get("relationships", [])}
    entities_by_id = {item.get("entity_id"): item for item in data.get("entities", [])}
    threads_by_id = {item.get("thread_id"): item for item in data.get("threads", [])}
    gaps_by_id = {item.get("gap_id"): item for item in data.get("gaps", [])}
    contradictions_by_id = {item.get("contradiction_id"): item for item in data.get("contradictions", [])}

    selected_events = _sort_events([events_by_id[item] for item in selected["events"] if item in events_by_id])
    selected_relationships = sorted((relationships_by_id[item] for item in selected["relationships"] if item in relationships_by_id), key=lambda item: item.get("relationship_id", ""))
    selected_entities = sorted((entities_by_id[item] for item in selected["entities"] if item in entities_by_id), key=lambda item: item.get("entity_id", ""))
    selected_threads = sorted((threads_by_id[item] for item in selected["threads"] if item in threads_by_id), key=lambda item: item.get("thread_id", ""))
    selected_gaps = sorted((gaps_by_id[item] for item in selected["gaps"] if item in gaps_by_id), key=lambda item: item.get("gap_id", ""))
    selected_contradictions = sorted((contradictions_by_id[item] for item in selected["contradictions"] if item in contradictions_by_id), key=lambda item: item.get("contradiction_id", ""))

    events = []
    for event in selected_events:
        item = _sanitize({key: value for key, value in event.items() if key != "source_payload"}, categories)
        for reference in item.get("entities", []):
            if isinstance(reference, dict) and "entity_id" in reference:
                reference["entity_id"] = _alias_entity(reference.get("entity_id"), aliases)
        if "host_id" in item:
            item["host_id"] = _alias_entity(item.get("host_id"), aliases)
        item["event_confidence"] = _event_confidence(event.get("event_id", ""), selected_relationships)
        item["report_provenance"] = _report_provenance("observed_event", [event.get("event_id")], source=event.get("provenance", {}))
        events.append(item)

    relationships = []
    for relationship in selected_relationships:
        item = _sanitize(relationship, categories)
        item["from"] = _alias_entity(item.get("from"), aliases)
        item["to"] = _alias_entity(item.get("to"), aliases)
        item["confidence_explanation"] = {
            "label": relationship.get("strength", "unknown"),
            "explanation": relationship.get("explanation", ""),
            "assumptions": relationship.get("assumptions", []),
            "weakening_factors": relationship.get("weakening_factors", []),
        }
        item["report_provenance"] = _report_provenance("derived_relationship", relationship.get("evidence_ids", []), relationship.get("derivation") or {"rule_id": relationship.get("rule_id"), "rule_version": relationship.get("rule_version", RULE_VERSION)})
        relationships.append(item)

    entities = []
    for entity in selected_entities:
        item = _sanitize(entity, categories)
        item["entity_id"] = _alias_entity(item.get("entity_id"), aliases)
        entity_category = _entity_category(entity)
        if entity_category:
            if "display_name" in entity and entity.get("display_name") is not None and entity_category in categories:
                item["display_name"] = _marker(entity_category)
            if "identifiers" in entity and entity_category in categories:
                item["identifiers"] = [_marker(entity_category) if value is not None else None for value in entity.get("identifiers", [])]
        item["report_provenance"] = _report_provenance("derived_entity", entity.get("event_ids", []), (entity.get("provenance") or {}).get("derivation"), source=(entity.get("provenance") or {}).get("source"))
        entities.append(item)

    threads = []
    for thread in selected_threads:
        item = _sanitize(thread, categories)
        item["entity_ids"] = [_alias_entity(value, aliases) for value in thread.get("entity_ids", [])]
        thread_events = [events_by_id[event_id] for event_id in thread.get("event_ids", []) if event_id in events_by_id]
        item["time_range"] = _time_range(thread_events)
        item["related_entities"] = sorted(_alias_entity(value, aliases) for value in thread.get("entity_ids", []))
        item["confidence_explanation"] = {"label": thread.get("confidence", "unknown"), "factors": sorted(thread.get("confidence_factors", [])), "relationship_ids": sorted(thread.get("relationship_ids", []))}
        item["report_provenance"] = _report_provenance("candidate_thread", thread.get("supporting_evidence_ids", thread.get("event_ids", [])), thread.get("derivation"))
        threads.append(item)

    gaps = []
    for gap in selected_gaps:
        item = _sanitize(gap, categories)
        item["report_provenance"] = _report_provenance("evidence_gap", gap.get("evidence_ids", []), gap.get("derivation"))
        gaps.append(item)

    contradictions = []
    for contradiction in selected_contradictions:
        item = _sanitize(contradiction, categories)
        item["report_provenance"] = _report_provenance("contradiction", contradiction.get("evidence_ids", []), contradiction.get("derivation"))
        contradictions.append(item)

    note_ids, decision_ids = _analyst_selection(data, selected)
    if selected["notes"] == {item.get("note_id") for item in data.get("notes", [])}:
        note_ids = {item.get("note_id") for item in data.get("notes", [])}
    if selected["decisions"] == {item.get("decision_id") for item in data.get("decisions", [])}:
        decision_ids = {item.get("decision_id") for item in data.get("decisions", [])}
    hypotheses = []
    for hypothesis in sorted((item for item in data.get("hypotheses", []) if item.get("hypothesis_id") in selected["hypotheses"]), key=lambda item: item.get("hypothesis_id", "")):
        item = _sanitize(hypothesis, categories)
        item["authorship"] = "analyst-authored"
        item["report_provenance"] = _report_provenance("analyst_hypothesis", hypothesis.get("supporting_evidence_ids", []) + hypothesis.get("weakening_evidence_ids", []) + hypothesis.get("unresolved_gap_ids", []), (hypothesis.get("provenance") or {}).get("derivation"))
        hypotheses.append(item)
    notes = []
    for note in sorted((item for item in data.get("notes", []) if item.get("note_id") in note_ids), key=lambda item: item.get("note_id", "")):
        item = _sanitize(note, categories)
        item["authorship"] = "analyst-authored"
        item["source_evidence"] = False
        item["report_provenance"] = _report_provenance("analyst_note", [], (note.get("provenance") or {}).get("derivation"))
        notes.append(item)
    decisions = []
    for decision in sorted((item for item in data.get("decisions", []) if item.get("decision_id") in decision_ids), key=lambda item: item.get("decision_id", "")):
        item = _sanitize(decision, categories)
        item["authorship"] = "analyst-authored"
        item["source_evidence"] = False
        item["report_provenance"] = _report_provenance("investigation_decision", decision.get("evidence_ids", []), (decision.get("provenance") or {}).get("derivation"))
        decisions.append(item)

    event_counts = Counter(event.get("event_type", "unknown") for event in selected_events)
    relationship_counts = Counter((relationship.get("type", "unknown"), relationship.get("strength", "unknown")) for relationship in selected_relationships)
    return {
        "events": events,
        "entities": entities,
        "relationships": relationships,
        "threads": threads,
        "gaps": gaps,
        "contradictions": contradictions,
        "investigation": {"hypotheses": hypotheses, "notes": notes, "decisions": decisions},
        "summaries": {
            "event_types": dict(sorted(event_counts.items())),
            "entity_types": dict(sorted(Counter(item.get("type", "unknown") for item in selected_entities).items())),
            "relationship_types_and_confidence": {f"{key[0]}:{key[1]}": value for key, value in sorted(relationship_counts.items())},
            "thread_confidence": dict(sorted(Counter(item.get("confidence", "unknown") for item in selected_threads).items())),
            "report_provenance": _report_provenance("report_summary", [event.get("event_id") for event in selected_events], REPORT_DERIVATION),
        },
        "time_summary": {**_time_summary(selected_events), "report_provenance": _report_provenance("time_summary", [event.get("event_id") for event in selected_events], REPORT_DERIVATION)},
    }


def _sanitize_graph(graph: dict, categories: set[str], aliases: dict[str, str]) -> dict:
    result = _sanitize(graph, categories)
    nodes = []
    for original, node in zip(graph.get("nodes", []), result.get("nodes", [])):
        if original.get("kind") == "entity":
            original_id = original.get("object_id")
            node["object_id"] = _alias_entity(original_id, aliases)
            node["node_id"] = _replace_entity_tokens(node.get("node_id"), aliases)
        category = {"user": "user", "host": "host", "file": "path", "device": "device", "ip": "ip", "domain": "domain"}.get(original.get("entity_type"))
        if category and category in categories:
            for key in ("label", "display_name"):
                if original.get(key) is not None:
                    node[key] = _marker(category)
        nodes.append(node)
    result["nodes"] = nodes
    for key in ("node_ids", "edge_ids"):
        result[key] = [_replace_entity_tokens(value, aliases) for value in result.get(key, [])]
    for edge in result.get("edges", []):
        edge["from"] = _replace_entity_tokens(edge.get("from"), aliases)
        edge["to"] = _replace_entity_tokens(edge.get("to"), aliases)
        edge["edge_id"] = _replace_entity_tokens(edge.get("edge_id"), aliases)
    if isinstance(result.get("start"), dict):
        result["start"]["id"] = _alias_entity(result["start"].get("id"), aliases)
        result["start"]["node_id"] = _replace_entity_tokens(result["start"].get("node_id"), aliases)
    return result


def _graph_export(data: dict, scope: str, scope_id: str | None, categories: set[str], aliases: dict[str, str], start_type: str | None, start_id: str | None, depth: int, limit: int) -> dict:
    if not start_type and not start_id:
        return {"selected": False, "summary": {"nodes": 0, "edges": 0}, "data": None}
    if not start_type or not start_id:
        raise ValueError("graph export requires both --graph-start-type and --graph-start-id")
    graph = build_graph(data, start_type, start_id, depth=depth, limit=limit, thread_id=scope_id if scope == "thread" else "")
    bounded = _sanitize_graph(graph, categories, aliases)
    graph_evidence_ids = sorted({evidence_id for item in graph.get("nodes", []) + graph.get("edges", []) for evidence_id in item.get("direct_evidence_ids", item.get("evidence_ids", []))})
    return {
        "selected": True,
        "summary": {
            "start": {"type": start_type, "id": _alias_entity(start_id, aliases)},
            "nodes": len(graph.get("nodes", [])),
            "edges": len(graph.get("edges", [])),
            "result_bounds": deepcopy(graph.get("result_bounds", {})),
            "truncated": any(bound.get("truncated") for bound in graph.get("result_bounds", {}).values()),
            "report_provenance": _report_provenance("bounded_graph_summary", graph_evidence_ids, REPORT_DERIVATION),
        },
        "data": bounded,
    }


def build_report(
    case_dir: Path,
    scope: str = "case",
    scope_id: str | None = None,
    redactions: Iterable[str] | None = None,
    redaction_config: Path | None = None,
    graph_start_type: str | None = None,
    graph_start_id: str | None = None,
    graph_depth: int = 1,
    graph_limit: int = 1000,
) -> dict:
    """Build a deterministic report projection from an analyzed case."""

    case_dir = Path(case_dir).resolve()
    if graph_depth < 0 or graph_depth > 3:
        raise ValueError("graph depth must be between 0 and 3")
    if graph_limit <= 0 or graph_limit > 2000:
        raise ValueError("graph limit must be between 1 and 2000")
    categories = load_redaction_config(redaction_config)
    categories.update(_normalise_categories(redactions))
    data = load_case(case_dir)
    manifest = data.get("manifest", {})
    if not manifest.get("case_id"):
        raise ValueError("case manifest is unavailable")
    config, config_warnings = _read_config(case_dir)
    selected = _select_scope(data, scope, scope_id)
    aliases = _entity_aliases(data, categories)
    projection = _enrich(data, selected, categories, aliases)
    warnings = sorted(data.get("warnings", []) + config_warnings, key=stable_json)
    public_manifest = {
        "schema_version": manifest.get("schema_version"),
        "case_id": manifest.get("case_id"),
        "import_batch_id": manifest.get("import_batch_id"),
        "analysis_config_hash": manifest.get("analysis_config_hash"),
        "inputs": [_public_input(item) for item in sorted(manifest.get("inputs", []), key=lambda item: item.get("file_id", ""))],
    }
    manifest_hash = _manifest_hash(manifest)
    analysis_id = stable_id("analysis", manifest_hash, manifest.get("analysis_config_hash"), length=16)
    graph = _graph_export(data, scope, scope_id, categories, aliases, graph_start_type, graph_start_id, graph_depth, graph_limit)
    limitations = [
        "Raw source evidence payloads are omitted by default; source hashes, evidence IDs, locators, and fingerprints remain available.",
        "Redacted values use explicit [REDACTED:category] markers and are not equivalent to missing values.",
        EVTX_VALIDATION_STATUS,
    ]
    if graph.get("summary", {}).get("truncated"):
        limitations.append("The selected graph export was bounded; omitted graph nodes or edges are identified by result_bounds.")
    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "report_version": REPORT_VERSION,
        "schema_version": SCHEMA_VERSION,
        "report_derivation": deepcopy(REPORT_DERIVATION),
        "scope": {"type": scope, "id": scope_id},
        "case": {
            "case_id": manifest.get("case_id"),
            "analysis_id": analysis_id,
            "manifest_hash": manifest_hash,
            "manifest": public_manifest,
            "source_file_hashes": {item.get("file_id"): item.get("sha256") for item in public_manifest["inputs"]},
        },
        "versions": {
            "schema_version": SCHEMA_VERSION,
            "report_schema_version": REPORT_SCHEMA_VERSION,
            "report_version": REPORT_VERSION,
            "parser_versions": config.get("parser_versions", {}),
            "correlation_rule_versions": config.get("rule_versions", {"core-correlation": RULE_VERSION}),
        },
        "analysis_configuration": _sanitize(config, categories),
        "evtx_validation_status": EVTX_VALIDATION_STATUS,
        "warnings": _sanitize(warnings, categories),
        "time_coverage": projection["time_summary"],
        "events": projection["events"],
        "threads": projection["threads"],
        "entities": projection["entities"],
        "relationships": projection["relationships"],
        "evidence_gaps": projection["gaps"],
        "contradictions": projection["contradictions"],
        "investigation": projection["investigation"],
        "summaries": projection["summaries"],
        "graph": graph,
        "redaction": {
            "categories": sorted(categories),
            "marker": REDACTION_MARKER,
            "raw_evidence_included": False,
            "missing_values_remain_null": True,
            "entity_references_pseudonymized": bool(aliases),
        },
        "limitations": limitations,
    }


def render_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + "\n"


def render_html(report: dict) -> str:
    body = html.escape(render_json(report), quote=False)
    title = html.escape(f"ForensicKit Investigation Report — {report['case']['case_id']}", quote=True)
    return (
        "<!doctype html>\n"
        "<html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'\">"
        f"<title>{title}</title>"
        "<style>body{font-family:system-ui,sans-serif;background:#f4f6f8;color:#17202a;margin:2rem}main{max-width:1100px;margin:auto;background:#fff;padding:2rem;border:1px solid #d9e0e6;border-radius:8px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#101820;color:#e8eef2;padding:1rem;border-radius:6px}h1{font-size:1.4rem}</style>"
        "</head><body><main>"
        f"<h1>{title}</h1><p>Self-contained offline report. Raw evidence payloads are omitted by default.</p>"
        f"<pre>{body}</pre>"
        "</main></body></html>\n"
    )


def render_markdown(report: dict) -> str:
    # Escape fence delimiters so analyst-authored text cannot terminate the
    # report's code block when rendered by a Markdown viewer.
    body = render_json(report).replace("```", "\\u0060\\u0060\\u0060")
    return f"# ForensicKit Investigation Report\n\nCase: `{report['case']['case_id']}`  \nAnalysis: `{report['case']['analysis_id']}`\n\n```json\n{body}```\n"


def export_report(report: dict, output: Path | None, format_name: str) -> str:
    format_name = format_name.casefold()
    if format_name == "json":
        content = render_json(report)
    elif format_name == "html":
        content = render_html(report)
    elif format_name in {"md", "markdown"}:
        content = render_markdown(report)
    else:
        raise ValueError("report format must be json, html, or markdown")
    if output is not None:
        output = Path(output)
        if output.exists():
            try:
                existing_hash = sha256_bytes(output.read_bytes())
            except OSError as exc:
                raise ValueError(f"report output cannot be read safely: {exc}") from exc
            protected_hashes = {value for value in report.get("case", {}).get("source_file_hashes", {}).values() if value}
            if existing_hash in protected_hashes:
                raise ValueError("report output matches a source evidence hash; source evidence is read-only")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8", newline="\n")
    return content


__all__ = [
    "EVTX_VALIDATION_STATUS",
    "REPORT_SCHEMA_VERSION",
    "REPORT_VERSION",
    "build_report",
    "export_report",
    "load_redaction_config",
    "render_html",
    "render_json",
    "render_markdown",
]
