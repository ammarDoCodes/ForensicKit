from __future__ import annotations
import json
import secrets
import shutil
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from .constants import DERIVED_FILES, PARSER_VERSIONS, RULE_VERSION, SCHEMA_VERSION, THREAD_VERSION
from .archive import ArchiveRejected, extract_archive, is_supported_archive
from .adapters import parse_evidence
from .manifest import build_manifest, discover_inputs
from .parser import parse_jsonl
from .timeutil import timestamp_sort_key
from .util import is_reparse_point, normalize_path, stable_id, stable_json

def write_json(path, value): path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
def write_jsonl(path, values): path.write_text("".join(stable_json(v) + "\n" for v in values), encoding="utf-8")
def _seconds(a, b):
    if not a.get("utc") or not b.get("utc"): return None
    return abs((datetime.fromisoformat(a["utc"].replace("Z", "+00:00")) - datetime.fromisoformat(b["utc"].replace("Z", "+00:00"))).total_seconds())
def _entity(event, prefix): return next((x["entity_id"] for x in event["entities"] if x["entity_id"].startswith(prefix)), None)
def _rel(kind, source, target, strength, explanation, events, distance=None, extra=None):
    evidence = sorted({e["event_id"] for e in events}); result = {"schema_version": SCHEMA_VERSION, "relationship_id": stable_id("rel", kind, source, target, evidence, RULE_VERSION, length=16), "type": kind, "from": source, "to": target, "strength": strength, "explanation": explanation, "rule_id": kind, "rule_version": RULE_VERSION, "evidence_ids": evidence, "time_distance_seconds": distance}
    if extra: result.update(extra)
    return result
def _entities(events):
    out = {}
    for event in events:
        for entity_id, kind, display, identifier in event.pop("_entity_records", []):
            row = out.setdefault(entity_id, {"schema_version": SCHEMA_VERSION, "entity_id": entity_id, "type": kind, "display_name": display, "identifiers": [], "event_ids": set(), "provenance": {"source_event_ids": set(), "derivation": {"algorithm": "entity-extractor", "version": "1.0.0"}}})
            if identifier not in row["identifiers"]: row["identifiers"].append(identifier)
            row["event_ids"].add(event["event_id"])
            row["provenance"]["source_event_ids"].add(event["event_id"])
    for row in out.values():
        row["identifiers"].sort(key=stable_json)
        row["event_ids"] = sorted(row["event_ids"])
        row["provenance"]["source_event_ids"] = sorted(row["provenance"]["source_event_ids"])
    return out
def _relationships(events):
    out = {}; hosts = defaultdict(list)
    def add(rel): out[rel["relationship_id"]] = rel
    for e in events:
        session, process, user = _entity(e, "session:"), _entity(e, "process:"), _entity(e, "user:")
        if session and process: add(_rel("session_membership", session, process, "moderate", "The record supplies both a session and process identifier; this is an explicit session-scoped association.", [e], extra={"assumptions": ["source session identifier is reliable"]}))
        if session and user: add(_rel("user_session_attribution", user, session, "moderate", "The record supplies a user and session identifier together.", [e]))
        if e.get("host_id"): hosts[e["host_id"]].append(e)
    processes = [e for e in events if e["event_type"] in {"process_start", "powershell_activity"} and _entity(e, "process:")]
    processes_by_path = defaultdict(list)
    processes_by_host = defaultdict(list)
    processes_by_host_pid = defaultdict(list)
    for process in processes:
        process_path = process["attributes"].get("image_path") or normalize_path(process["attributes"].get("image"))
        if process_path:
            processes_by_path[(process.get("host_id"), process_path)].append(process)
        processes_by_host[process.get("host_id")].append(process)
        if process["attributes"].get("pid"):
            processes_by_host_pid[(process.get("host_id"), process["attributes"]["pid"])].append(process)
    files = [e for e in events if e["event_type"] in {"file_create", "file_delete"} and _entity(e, "file:")]
    for f in files:
        path = f["attributes"].get("file_path")
        for p in processes_by_path.get((f.get("host_id"), path), []):
            distance = _seconds(f["observed_at"], p["observed_at"])
            if distance is None or distance > 3600: continue
            if f["event_type"] == "file_create" and f["observed_at"].get("utc") > p["observed_at"].get("utc"): continue
            add(_rel("file_process_path_and_time", _entity(f, "file:"), _entity(p, "process:"), "moderate", f"Normalized image path matches the file path and execution occurred {int(distance)} seconds from the file observation; path matching alone does not prove causation.", [f, p], distance, {"assumptions": ["host identity is comparable", "path normalization is valid"], "weakening_factors": ["path may be reused", "execution source is not independently verified"]}))
    # Parent/child links require a scoped PID or process GUID and compatible ordering.
    for child in processes:
        child_attrs = child["attributes"]
        parent_guid = child_attrs.get("parent_process_guid")
        parent_pid = child_attrs.get("parent_pid")
        if not parent_guid and not parent_pid:
            continue
        candidates = [p for p in processes if p is not child and p.get("host_id") == child.get("host_id") and ((parent_guid and p["attributes"].get("process_guid") == parent_guid) or (parent_pid and p["attributes"].get("pid") == parent_pid))]
        candidates = [p for p in candidates if not child["observed_at"].get("utc") or not p["observed_at"].get("utc") or p["observed_at"]["utc"] <= child["observed_at"]["utc"]]
        if candidates:
            parent = max(candidates, key=lambda p: (p["observed_at"].get("utc") or "", p["event_id"]))
            distance = _seconds(parent["observed_at"], child["observed_at"])
            if distance is None or distance <= 86400:
                add(_rel("parent_child_process", _entity(parent, "process:"), _entity(child, "process:"), "high" if parent_guid else "moderate", "The child record supplies a parent process GUID." if parent_guid else "The child record supplies a parent PID scoped to the same host and compatible process start ordering.", [parent, child], distance, {"assumptions": ["host identity is comparable", "PID has not been reused across the compatible interval"], "weakening_factors": [] if parent_guid else ["PID reuse cannot be excluded without process lifetime data"]}))
    # Device/file links require an explicit shared device, volume, or mount identifier.
    device_events = [e for e in events if e["event_type"] in {"device_connect", "device_observation"} and _entity(e, "device:")]
    for device_event in device_events:
        device_id = device_event["attributes"].get("device_id") or device_event["attributes"].get("volume_serial")
        for file_event in files:
            if device_event.get("host_id") != file_event.get("host_id") or not device_id:
                continue
            file_device = file_event["attributes"].get("device_id") or file_event["attributes"].get("volume_serial")
            if file_device != device_id:
                continue
            distance = _seconds(device_event["observed_at"], file_event["observed_at"])
            if distance is not None and distance <= 86400:
                add(_rel("device_file_observation", _entity(device_event, "device:"), _entity(file_event, "file:"), "moderate", "The device and file records provide the same explicit device or volume identifier; this does not prove transfer or execution.", [device_event, file_event], distance, {"assumptions": ["device identifier is source-comparable"], "weakening_factors": ["file activity does not establish data transfer direction"]}))
    networks = [e for e in events if e["event_type"] == "network_connection"]
    for n in networks:
        pid = n["attributes"].get("pid") or n["attributes"].get("source_process_id"); candidates = processes_by_host_pid.get((n.get("host_id"), pid), []) if pid else processes_by_host.get(n.get("host_id"), [])
        if not candidates: continue
        p = min(candidates, key=lambda e: (_seconds(n["observed_at"], e["observed_at"]) or 10**9, e["event_id"])); distance = _seconds(n["observed_at"], p["observed_at"])
        if distance is not None and distance <= 300:
            target = _entity(n, "ip:") or _entity(n, "domain:") or n.get("host_id"); explicit = bool(pid)
            if not target: continue
            add(_rel("process_network_link", _entity(p, "process:"), target, "moderate" if explicit else "weak", "The network record contains the same process identifier." if explicit else "The association uses only the same host and a bounded five-minute window; temporal proximity is not proof of process ownership.", [p, n], distance, {"assumptions": ["host clock comparison is meaningful"], "weakening_factors": [] if explicit else ["no source process identifier"]}))
    for host_events in hosts.values():
        ordered = sorted(host_events, key=lambda e: (timestamp_sort_key(e["observed_at"]), e["event_id"]))
        for a, b in zip(ordered, ordered[1:]):
            distance = _seconds(a["observed_at"], b["observed_at"])
            if distance is None or distance > 300: continue
            left = _entity(a, "process:") or _entity(a, "file:") or _entity(a, "device:") or _entity(a, "user:") or a.get("host_id"); right = _entity(b, "process:") or _entity(b, "file:") or _entity(b, "device:") or _entity(b, "user:") or b.get("host_id")
            if left and right and left != right: add(_rel("temporal_proximity", left, right, "weak", f"Adjacent observations share host {a.get('host_id')} and are {int(distance)} seconds apart; contextual only, not causation or attribution.", [a, b], distance, {"assumptions": ["source timestamps are comparable"], "weakening_factors": ["no direct identifier links the observations"]}))
    return sorted(out.values(), key=lambda r: r["relationship_id"])
def _gaps(events, relationships=None):
    result = []
    for e in events:
        if e["event_type"] == "process_start" and not e["attributes"].get("parent_pid") and not e["attributes"].get("parent_process_guid"): result.append({"schema_version": SCHEMA_VERSION, "gap_id": stable_id("gap", "missing-parent", e["event_id"], length=16), "type": "missing_parent_process_reference", "description": "Process execution has no parent PID or parent process GUID in the imported record.", "affected_event_ids": [e["event_id"]], "evidence_ids": [e["event_id"]], "reason": "input_absence", "suggested_next_evidence": "Process creation telemetry with parent process identifier", "impact": "moderate", "derivation": {"rule_id": "gap-missing-parent", "rule_version": RULE_VERSION}})
        if e["event_type"] == "process_start" and (e["attributes"].get("parent_pid") or e["attributes"].get("parent_process_guid")) and relationships is not None:
            process_id = _entity(e, "process:")
            if not any(r["type"] == "parent_child_process" and r["to"] == process_id for r in relationships):
                result.append({"schema_version": SCHEMA_VERSION, "gap_id": stable_id("gap", "unresolved-parent", e["event_id"], length=16), "type": "unresolved_parent_process_reference", "description": "Process record names a parent process, but no compatible parent event was imported.", "affected_event_ids": [e["event_id"]], "evidence_ids": [e["event_id"]], "reason": "identity_ambiguity", "suggested_next_evidence": "Earlier process creation records or process lifetime telemetry", "impact": "moderate", "derivation": {"rule_id": "gap-unresolved-parent", "rule_version": RULE_VERSION}})
        if e["event_type"] == "network_connection" and not e["attributes"].get("pid"): result.append({"schema_version": SCHEMA_VERSION, "gap_id": stable_id("gap", "network-process", e["event_id"], length=16), "type": "network_process_identifier_missing", "description": "Network observation has no source process identifier.", "affected_event_ids": [e["event_id"]], "evidence_ids": [e["event_id"]], "reason": "input_absence", "suggested_next_evidence": "Network telemetry with process ID", "impact": "high", "derivation": {"rule_id": "gap-network-process", "rule_version": RULE_VERSION}})
    return sorted(result, key=lambda x: x["gap_id"])
def _contradictions(events, relationships):
    sessions, processes = defaultdict(lambda: defaultdict(list)), defaultdict(lambda: defaultdict(list))
    for e in events:
        s, u, p, image = _entity(e, "session:"), _entity(e, "user:"), _entity(e, "process:"), e["attributes"].get("image")
        if s and u: sessions[s][u].append(e["event_id"])
        if p and image: processes[p][image.casefold()].append(e["event_id"])
    result = []
    for s, users in sessions.items():
        if len(users) > 1:
            evidence = sorted(i for ids in users.values() for i in ids); result.append({"schema_version": SCHEMA_VERSION, "contradiction_id": stable_id("contra", "session", s, evidence, length=16), "type": "incompatible_session_attribution", "severity": "medium", "description": f"Session {s} is attributed to more than one user.", "evidence_ids": evidence, "affected_relationship_ids": sorted(r["relationship_id"] for r in relationships if r["type"] == "user_session_attribution" and r["to"] == s), "resolution_status": "unresolved", "possible_causes": ["clock error", "session reuse", "source inconsistency"], "derivation": {"rule_id": "contradiction-session-attribution", "rule_version": RULE_VERSION}})
    for p, images in processes.items():
        if len(images) > 1:
            evidence = sorted(i for ids in images.values() for i in ids); result.append({"schema_version": SCHEMA_VERSION, "contradiction_id": stable_id("contra", "process", p, evidence, length=16), "type": "process_identity_ambiguity", "severity": "medium", "description": "The same scoped process identifier is associated with multiple images.", "evidence_ids": evidence, "affected_relationship_ids": [], "resolution_status": "unresolved", "possible_causes": ["PID reuse", "source inconsistency"], "derivation": {"rule_id": "contradiction-process-identity", "rule_version": RULE_VERSION}})
    return sorted(result, key=lambda x: x["contradiction_id"])
def _threads(events, relationships, gaps, contradictions):
    parent = {e["event_id"]: e["event_id"] for e in events}
    def find(x):
        while parent[x] != x: parent[x] = parent[parent[x]]; x = parent[x]
        return x
    def union(a, b):
        if a in parent and b in parent: parent[find(a)] = find(b)
    events_by_entity = defaultdict(list)
    for event in events:
        for entity in event["entities"]:
            events_by_entity[entity["entity_id"]].append(event["event_id"])
    for r in relationships:
        for e in r["evidence_ids"][1:]: union(r["evidence_ids"][0], e)
        for entity_id in (r["from"], r["to"]):
            related = events_by_entity.get(entity_id, [])
            for e in related[1:]: union(related[0], e)
    groups = defaultdict(list); by_id = {e["event_id"]: e for e in events}
    for e in events: groups[find(e["event_id"])].append(e["event_id"])
    result = []
    for ids in groups.values():
        ids = sorted(ids, key=lambda i: (timestamp_sort_key(by_id[i]["observed_at"]), i)); rels = [r for r in relationships if set(r["evidence_ids"]).issubset(ids)]
        if len(ids) < 2 or len({by_id[i]["event_type"] for i in ids}) < 2: continue
        strengths = {r["strength"] for r in rels}; confidence = "high" if "high" in strengths else "moderate" if "moderate" in strengths else "weak" if rels else "unknown"
        contra = sorted(c["contradiction_id"] for c in contradictions if set(c["evidence_ids"]) & set(ids));
        if contra and confidence == "high": confidence = "moderate"
        result.append({"schema_version": SCHEMA_VERSION, "thread_id": stable_id("thread", ids, [r["relationship_id"] for r in rels], length=16), "title": "Candidate: " + " → ".join(by_id[i]["event_type"].replace("_", " ") for i in ids[:3]), "status": "candidate", "confidence": confidence, "event_ids": ids, "entity_ids": sorted({x["entity_id"] for i in ids for x in by_id[i]["entities"] if not x["entity_id"].startswith("source:")}), "relationship_ids": sorted(r["relationship_id"] for r in rels), "rule_ids": sorted({r["rule_id"] for r in rels}), "supporting_evidence_ids": ids, "contradiction_ids": contra, "gap_ids": sorted(g["gap_id"] for g in gaps if set(g["affected_event_ids"]) & set(ids)), "derivation": {"algorithm": "thread-builder", "version": THREAD_VERSION}, "confidence_factors": sorted({r["type"] + ":" + r["strength"] for r in rels})})
    return sorted(result, key=lambda x: x["thread_id"])
def _analyze_directory(case_dir: Path, input_path: Path, pre_warnings=None, archive_info=None, format_hint=None):
    case_dir = case_dir.resolve(); case_dir.mkdir(parents=True, exist_ok=True); manifest_path = case_dir / "manifest.json"; existing = None
    if manifest_path.exists():
        try: existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError: pass
    files, imported_warnings = discover_inputs(input_path, case_dir); manifest, contents = build_manifest(case_dir, input_path, files, existing, archive_info, format_hint); warnings, events = list(pre_warnings or []) + list(imported_warnings), []
    for item in manifest["inputs"]:
        if item["detected_format"] == "unsupported": warnings.append({"schema_version": SCHEMA_VERSION, "severity": "warning", "code": "UNSUPPORTED_FORMAT", "message": f"No parser is available for {item['relative_path']}.", "source_file_id": item["file_id"], "source_locator": "file"}); continue
        parsed, diagnostics = parse_evidence(contents[item["file_id"]], item["file_id"], item["relative_path"], item["detected_format"], manifest["import_batch_id"]); events.extend(parsed); warnings.extend(diagnostics)
    file_hashes = {item["file_id"]: item["sha256"] for item in manifest["inputs"]}
    events.sort(key=lambda e: (timestamp_sort_key(e["observed_at"]), file_hashes.get(e["provenance"]["source_file_id"], ""), e["provenance"]["source_locator"], e["event_id"])); entities = _entities(events); relationships = _relationships(events); gaps = _gaps(events, relationships); contradictions = _contradictions(events, relationships); threads = _threads(events, relationships, gaps, contradictions); warnings.sort(key=stable_json)
    write_json(manifest_path, manifest); write_json(case_dir / "analysis-config.json", {"schema_version": SCHEMA_VERSION, "parser_versions": PARSER_VERSIONS, "rule_versions": {"core-correlation": RULE_VERSION}, "limits": {"temporal_proximity_seconds": 300, "file_process_seconds": 3600, "evtx_record_count": 250000, "evtx_record_bytes": 2097152}}); write_jsonl(case_dir / "normalized-events.jsonl", events); write_json(case_dir / "entities.json", sorted(entities.values(), key=lambda x: x["entity_id"])); write_jsonl(case_dir / "relationships.jsonl", relationships); write_json(case_dir / "threads.json", threads); write_json(case_dir / "gaps.json", gaps); write_json(case_dir / "contradictions.json", contradictions); write_json(case_dir / "warnings.json", warnings)
    for name in ("hypotheses.json", "notes.json", "decisions.json"):
        if not (case_dir / name).exists(): write_json(case_dir / name, [])
    entity_ids = set(entities)
    for relationship in relationships:
        if relationship["from"] not in entity_ids or relationship["to"] not in entity_ids:
            raise ValueError(f"relationship has unresolved entity reference: {relationship['relationship_id']}")
        if not set(relationship["evidence_ids"]).issubset({event["event_id"] for event in events}):
            raise ValueError(f"relationship has unresolved evidence reference: {relationship['relationship_id']}")
    event_ids = {event["event_id"] for event in events}; relationship_ids = {relationship["relationship_id"] for relationship in relationships}
    gap_ids = {gap["gap_id"] for gap in gaps}; contradiction_ids = {contradiction["contradiction_id"] for contradiction in contradictions}
    for entity in entities.values():
        if not set(entity["event_ids"]).issubset(event_ids):
            raise ValueError(f"entity has unresolved event reference: {entity['entity_id']}")
    for gap in gaps:
        if not set(gap["evidence_ids"]).issubset(event_ids):
            raise ValueError(f"gap has unresolved evidence reference: {gap['gap_id']}")
    for contradiction in contradictions:
        if not set(contradiction["evidence_ids"]).issubset(event_ids) or not set(contradiction["affected_relationship_ids"]).issubset(relationship_ids):
            raise ValueError(f"contradiction has unresolved reference: {contradiction['contradiction_id']}")
    for thread in threads:
        if not set(thread["event_ids"]).issubset(event_ids) or not set(thread["entity_ids"]).issubset(entity_ids) or not set(thread["relationship_ids"]).issubset(relationship_ids) or not set(thread["gap_ids"]).issubset(gap_ids) or not set(thread["contradiction_ids"]).issubset(contradiction_ids):
            raise ValueError(f"thread has unresolved reference: {thread['thread_id']}")
    return {"manifest": manifest, "events": events, "entities": list(entities.values()), "relationships": relationships, "threads": threads, "gaps": gaps, "contradictions": contradictions, "warnings": warnings}


def analyze_case(case_dir: Path, input_path: Path, format_hint: str | None = None):
    """Analyze a directory or safely extract and analyze one supported archive."""
    case_dir = Path(case_dir)
    if case_dir.is_symlink() or (case_dir.exists() and is_reparse_point(case_dir)):
        raise ValueError("case output directory must not be a link or reparse point")
    case_dir = case_dir.resolve()
    case_dir.mkdir(parents=True, exist_ok=True)
    input_path = Path(input_path)
    if input_path.is_symlink() or (input_path.exists() and is_reparse_point(input_path)):
        raise ValueError("symbolic-link or reparse-point import roots are not allowed")
    input_path = input_path.resolve()
    for name in DERIVED_FILES:
        output = case_dir / name
        if output.is_symlink() or (output.exists() and (is_reparse_point(output) or not output.is_file())):
            raise ValueError("case output contains an unsafe derived-file path")
        if input_path.is_file() and output.exists():
            try:
                if output.samefile(input_path):
                    raise ValueError("source input conflicts with a derived output file")
            except OSError as exc:
                raise ValueError("source/output file identity could not be verified") from exc
        if input_path.is_file() and output == input_path:
            raise ValueError("source input conflicts with a derived output file")
    if input_path.is_file() and is_supported_archive(input_path):
        for _ in range(8):
            staging = case_dir / (".forensickit-import-" + secrets.token_hex(16))
            try:
                staging.mkdir()
                break
            except FileExistsError:
                continue
        else:
            raise ValueError("an unused archive scratch directory could not be created")
        extraction_root = staging / "evidence"
        try:
            try:
                diagnostics, archive_info = extract_archive(input_path, extraction_root)
            except ArchiveRejected as exc:
                source_id = "archive:" + __import__("hashlib").sha256(input_path.read_bytes()).hexdigest()[:16]
                warning = {"schema_version": SCHEMA_VERSION, "severity": "warning", "code": exc.code, "message": str(exc), "source_file_id": source_id, "source_locator": exc.member or "archive"}
                write_json(case_dir / "warnings.json", [warning])
                raise ValueError(f"{exc.code}: {exc}") from exc
            archive_info["relative_path"] = input_path.name
            return _analyze_directory(case_dir, extraction_root, diagnostics, archive_info, format_hint)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
    return _analyze_directory(case_dir, input_path, format_hint=format_hint)
def _load(case_dir):
    def read(name, default):
        path = case_dir / name
        if not path.exists(): return default
        return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()] if name.endswith(".jsonl") else json.loads(path.read_text(encoding="utf-8"))
    return {"manifest": read("manifest.json", {}), "events": read("normalized-events.jsonl", []), "entities": read("entities.json", []), "relationships": read("relationships.jsonl", []), "threads": read("threads.json", []), "gaps": read("gaps.json", []), "contradictions": read("contradictions.json", []), "warnings": read("warnings.json", []), "hypotheses": read("hypotheses.json", []), "notes": read("notes.json", []), "decisions": read("decisions.json", [])}
load_case = _load
def pivot(case_dir, entity_id, depth=1):
    data = _load(case_dir)
    try:
        depth = int(depth)
    except (TypeError, ValueError) as exc:
        raise ValueError("pivot depth must be an integer") from exc
    if depth < 0 or depth > 3:
        raise ValueError("pivot depth must be between 0 and 3")
    known_entities = {entity["entity_id"] for entity in data["entities"]}
    if entity_id not in known_entities:
        raise ValueError(f"entity not found: {entity_id}")
    expanded = {entity_id}
    frontier = {entity_id}
    for _ in range(depth):
        neighbors = {
            endpoint
            for relationship in data["relationships"]
            if relationship["from"] in frontier or relationship["to"] in frontier
            for endpoint in (relationship["from"], relationship["to"])
            if endpoint in known_entities
        } - expanded
        expanded.update(neighbors)
        frontier = neighbors
        if not frontier:
            break
    event_ids = [
        event["event_id"]
        for event in data["events"]
        if any(entity["entity_id"] in expanded for entity in event.get("entities", []))
    ]
    event_ids = sorted(
        event_ids,
        key=lambda event_id: (
            timestamp_sort_key(next(event["observed_at"] for event in data["events"] if event["event_id"] == event_id)),
            event_id,
        ),
    )
    event_id_set = set(event_ids)
    rels = sorted(
        [r for r in data["relationships"] if r["from"] in expanded or r["to"] in expanded],
        key=lambda relationship: relationship["relationship_id"],
    )
    relationship_ids = {relationship["relationship_id"] for relationship in rels}
    threads = sorted(
        [
            thread
            for thread in data["threads"]
            if set(thread.get("entity_ids", [])) & expanded
            or set(thread.get("event_ids", [])) & event_id_set
            or set(thread.get("relationship_ids", [])) & relationship_ids
        ],
        key=lambda thread: thread["thread_id"],
    )
    gap_candidates = [
        gap
        for gap in data["gaps"]
        if set(gap.get("affected_event_ids", [])) & event_id_set
        or set(gap.get("evidence_ids", [])) & event_id_set
    ]
    gap_ids = {gap["gap_id"] for gap in gap_candidates}
    contradiction_candidates = [
        contradiction
        for contradiction in data["contradictions"]
        if set(contradiction.get("evidence_ids", [])) & event_id_set
        or set(contradiction.get("affected_relationship_ids", [])) & relationship_ids
    ]
    contradiction_ids = {contradiction["contradiction_id"] for contradiction in contradiction_candidates}
    reference_ids = event_id_set | relationship_ids | gap_ids | contradiction_ids
    hypotheses = sorted(
        [
            hypothesis
            for hypothesis in data["hypotheses"]
            if set(hypothesis.get("supporting_evidence_ids", [])) & reference_ids
            or set(hypothesis.get("weakening_evidence_ids", [])) & reference_ids
            or set(hypothesis.get("unresolved_gap_ids", [])) & gap_ids
        ],
        key=lambda hypothesis: hypothesis["hypothesis_id"],
    )
    events = [event for event in data["events"] if event["event_id"] in event_id_set]
    uncertain = [event["event_id"] for event in events if event.get("observed_at", {}).get("quality") != "exact"]
    expanded_entities = sorted(expanded)
    return {
        "schema_version": SCHEMA_VERSION,
        "entity_id": entity_id,
        "depth": depth,
        "expanded_entity_ids": expanded_entities,
        "entities": [entity for entity in data["entities"] if entity["entity_id"] in expanded],
        "event_ids": event_ids,
        "events": events,
        "relationship_ids": sorted(relationship_ids),
        "relationships": rels,
        "thread_ids": [thread["thread_id"] for thread in threads],
        "threads": threads,
        "hypothesis_ids": [hypothesis["hypothesis_id"] for hypothesis in hypotheses],
        "hypotheses": hypotheses,
        "gap_ids": sorted(gap_ids),
        "gaps": sorted(gap_candidates, key=lambda gap: gap["gap_id"]),
        "contradiction_ids": sorted(contradiction_ids),
        "contradictions": sorted(contradiction_candidates, key=lambda contradiction: contradiction["contradiction_id"]),
        "time_uncertain": bool(uncertain),
        "uncertain_event_ids": sorted(uncertain),
    }
def replay(case_dir, thread_id):
    data = _load(case_dir); thread = next((t for t in data["threads"] if t["thread_id"] == thread_id), None)
    if thread is None: raise ValueError(f"thread not found: {thread_id}")
    by_id = {e["event_id"]: e for e in data["events"]}; replay_events = [by_id[i] for i in thread["event_ids"] if i in by_id]; rels = [r for r in data["relationships"] if r["relationship_id"] in thread["relationship_ids"]]; gaps = [g for g in data["gaps"] if g["gap_id"] in thread["gap_ids"]]; contradictions = [c for c in data["contradictions"] if c["contradiction_id"] in thread["contradiction_ids"]]
    return {"schema_version": SCHEMA_VERSION, "thread_id": thread_id, "confidence": thread["confidence"], "confidence_factors": thread.get("confidence_factors", []), "time_uncertain": any(e["observed_at"].get("quality") != "exact" for e in replay_events), "uncertain_event_ids": [e["event_id"] for e in replay_events if e["observed_at"].get("quality") != "exact"], "events": replay_events, "relationship_ids": thread["relationship_ids"], "relationships": rels, "gap_ids": thread["gap_ids"], "gaps": gaps, "contradiction_ids": thread["contradiction_ids"], "contradictions": contradictions}
