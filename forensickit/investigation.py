from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .analysis import _load, write_json
from .constants import RULE_VERSION, SCHEMA_VERSION
from .util import stable_id


ANALYST_VERSION = "1.0.0"
HYPOTHESIS_STATUSES = {"open", "in_review", "supported", "weakened", "accepted", "rejected", "inconclusive"}
DECISION_STATUSES = {"open", "in_review", "closed"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _save(case_dir: Path, name: str, values: list[dict]) -> None:
    write_json(case_dir / name, sorted(values, key=lambda value: value.get("hypothesis_id", value.get("note_id", value.get("decision_id", "")))))


def _valid_evidence(data: dict) -> set[str]:
    return {event["event_id"] for event in data["events"]} | {relationship["relationship_id"] for relationship in data["relationships"]} | {gap["gap_id"] for gap in data["gaps"]} | {item["contradiction_id"] for item in data["contradictions"]}


def _validate_evidence(data: dict, values: list[str], field: str) -> list[str]:
    values = sorted(set(values))
    unknown = [value for value in values if value not in _valid_evidence(data)]
    if unknown:
        raise ValueError(f"{field} contains unknown evidence references: {', '.join(unknown)}")
    return values


def create_hypothesis(case_dir: Path, statement: str, supporting=None, weakening=None, unresolved_gaps=None, status: str = "open", analyst: str = "local") -> dict:
    data = _load(case_dir)
    statement = statement.strip()
    if not statement:
        raise ValueError("hypothesis statement cannot be empty")
    if status not in HYPOTHESIS_STATUSES:
        raise ValueError(f"unsupported hypothesis status: {status}")
    supporting = _validate_evidence(data, supporting or [], "supporting_evidence_ids")
    weakening = _validate_evidence(data, weakening or [], "weakening_evidence_ids")
    unresolved_gaps = _validate_evidence(data, unresolved_gaps or [], "unresolved_gap_ids")
    hypothesis_id = stable_id("hyp", data["manifest"].get("case_id"), statement, length=16)
    result = {"schema_version": SCHEMA_VERSION, "hypothesis_id": hypothesis_id, "statement": statement, "status": status, "supporting_evidence_ids": supporting, "weakening_evidence_ids": weakening, "unresolved_gap_ids": unresolved_gaps, "analyst_note": "", "created_at_utc": _now(), "updated_at_utc": _now(), "analyst": analyst, "provenance": {"evidence_ids": sorted(set(supporting + weakening + unresolved_gaps)), "derivation": {"algorithm": "analyst-authored", "version": ANALYST_VERSION}}}
    values = [item for item in data["hypotheses"] if item["hypothesis_id"] != hypothesis_id]
    values.append(result)
    _save(case_dir, "hypotheses.json", values)
    return result


def update_hypothesis(case_dir: Path, hypothesis_id: str, status: str | None = None, supporting=None, weakening=None, unresolved_gaps=None, analyst_note: str | None = None) -> dict:
    data = _load(case_dir)
    item = next((item for item in data["hypotheses"] if item["hypothesis_id"] == hypothesis_id), None)
    if item is None:
        raise ValueError(f"hypothesis not found: {hypothesis_id}")
    if status is not None:
        if status not in HYPOTHESIS_STATUSES:
            raise ValueError(f"unsupported hypothesis status: {status}")
        item["status"] = status
    if supporting is not None:
        item["supporting_evidence_ids"] = _validate_evidence(data, item.get("supporting_evidence_ids", []) + supporting, "supporting_evidence_ids")
    if weakening is not None:
        item["weakening_evidence_ids"] = _validate_evidence(data, item.get("weakening_evidence_ids", []) + weakening, "weakening_evidence_ids")
    if unresolved_gaps is not None:
        item["unresolved_gap_ids"] = _validate_evidence(data, item.get("unresolved_gap_ids", []) + unresolved_gaps, "unresolved_gap_ids")
    if analyst_note is not None:
        item["analyst_note"] = analyst_note
    item["updated_at_utc"] = _now()
    item["provenance"]["evidence_ids"] = sorted(set(item.get("supporting_evidence_ids", []) + item.get("weakening_evidence_ids", []) + item.get("unresolved_gap_ids", [])))
    _save(case_dir, "hypotheses.json", data["hypotheses"])
    return item


def create_note(case_dir: Path, text: str, target_type: str | None = None, target_id: str | None = None, analyst: str = "local") -> dict:
    data = _load(case_dir)
    if not text.strip():
        raise ValueError("note text cannot be empty")
    known = _valid_evidence(data) | {entity["entity_id"] for entity in data["entities"]} | {thread["thread_id"] for thread in data["threads"]}
    if target_id and target_id not in known:
        raise ValueError(f"note target not found: {target_id}")
    note_id = stable_id("note", data["manifest"].get("case_id"), target_type or "case", target_id or "", text, length=16)
    item = {"schema_version": SCHEMA_VERSION, "note_id": note_id, "text": text, "target_type": target_type, "target_id": target_id, "created_at_utc": _now(), "analyst": analyst, "provenance": {"derivation": {"algorithm": "analyst-authored", "version": ANALYST_VERSION}}}
    values = [value for value in data["notes"] if value["note_id"] != note_id] + [item]
    _save(case_dir, "notes.json", values)
    return item


def create_decision(case_dir: Path, statement: str, status: str = "open", evidence=None, rationale: str = "", analyst: str = "local") -> dict:
    data = _load(case_dir)
    if status not in DECISION_STATUSES:
        raise ValueError(f"unsupported decision status: {status}")
    evidence = _validate_evidence(data, evidence or [], "evidence_ids")
    decision_id = stable_id("decision", data["manifest"].get("case_id"), statement, length=16)
    item = {"schema_version": SCHEMA_VERSION, "decision_id": decision_id, "statement": statement.strip(), "status": status, "evidence_ids": evidence, "rationale": rationale, "created_at_utc": _now(), "updated_at_utc": _now(), "analyst": analyst, "provenance": {"evidence_ids": evidence, "derivation": {"algorithm": "analyst-authored", "version": ANALYST_VERSION}}}
    values = [value for value in data["decisions"] if value["decision_id"] != decision_id] + [item]
    _save(case_dir, "decisions.json", values)
    return item


def update_decision(case_dir: Path, decision_id: str, status: str | None = None, rationale: str | None = None) -> dict:
    data = _load(case_dir)
    item = next((item for item in data["decisions"] if item["decision_id"] == decision_id), None)
    if item is None:
        raise ValueError(f"decision not found: {decision_id}")
    if status is not None:
        if status not in DECISION_STATUSES:
            raise ValueError(f"unsupported decision status: {status}")
        item["status"] = status
    if rationale is not None:
        item["rationale"] = rationale
    item["updated_at_utc"] = _now()
    _save(case_dir, "decisions.json", data["decisions"])
    return item


def list_investigation(case_dir: Path, kind: str) -> list[dict]:
    data = _load(case_dir)
    return data[{"hypotheses": "hypotheses", "notes": "notes", "decisions": "decisions"}[kind]]
