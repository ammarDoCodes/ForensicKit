from __future__ import annotations
import json
from typing import Any
from .constants import EVENT_TIME_KEYS, EVENT_TYPE_ALIASES, PARSER_NAME, PARSER_VERSION, SCHEMA_VERSION
from .models import Diagnostic
from .timeutil import normalize_timestamp
from .util import clean_text, normalize_identifier, normalize_path, sha256_text, stable_id
def _first(record: dict, *keys: str) -> Any:
    for key in keys:
        if key in record and record[key] not in (None, ""): return record[key]
    return None
def _entity(entity_type: str, value: str, host: str | None = None) -> str:
    return f"{entity_type}:{host}:{value}" if entity_type in {"user", "session", "process", "file", "device"} and host else f"{entity_type}:{value}"
def _event_type(record: dict) -> str:
    value = clean_text(_first(record, "event_type", "type", "kind")) or "unknown"
    return EVENT_TYPE_ALIASES.get(value.casefold(), value.casefold().replace(" ", "_"))
MAX_RECORD_COUNT = 1_000_000

def parse_jsonl(raw: bytes, file_id: str, source_path: str, import_batch_id: str | None = None, parser_name: str = PARSER_NAME, parser_version: str = PARSER_VERSION):
    events, diagnostics = [], []
    try: text = raw.decode("utf-8-sig")
    except UnicodeDecodeError: return events, [Diagnostic("warning", "INVALID_ENCODING", "File is not valid UTF-8.", file_id, "file").as_dict()]
    for number, line in enumerate(text.splitlines(), 1):
        if number > MAX_RECORD_COUNT:
            diagnostics.append(Diagnostic("warning", "RECORD_COUNT_LIMIT", f"Parsing stopped after {MAX_RECORD_COUNT} records.", file_id, f"record[{number}]").as_dict())
            break
        locator = f"record[{number}]"
        if not line.strip(): continue
        fingerprint = sha256_text(line)
        try: source = json.loads(line)
        except json.JSONDecodeError as exc:
            diagnostics.append(Diagnostic("warning", "MALFORMED_JSON", f"Record is not valid JSON: {exc.msg}.", file_id, locator).as_dict()); continue
        if not isinstance(source, dict): diagnostics.append(Diagnostic("warning", "RECORD_NOT_OBJECT", "JSONL record must be an object.", file_id, locator).as_dict()); continue
        event, warnings = canonical_event(source, file_id, locator, source_path, fingerprint, import_batch_id, parser_name, parser_version); events.append(event); diagnostics.extend(warnings)
    return events, diagnostics
def canonical_event(source: dict, file_id: str, locator: str, source_path: str, fingerprint: str, import_batch_id: str | None = None, parser_name: str = PARSER_NAME, parser_version: str = PARSER_VERSION, provenance_extra: dict | None = None):
    warnings = []; event_type = _event_type(source); timestamp_value = next((source[k] for k in EVENT_TIME_KEYS if k in source), None); observed_at, warning_code = normalize_timestamp(timestamp_value)
    if warning_code: warnings.append(Diagnostic("warning", warning_code, "Record has no usable timestamp; retained but excluded from time-window rules.", file_id, locator).as_dict())
    host = normalize_identifier(_first(source, "host_id", "host", "hostname", "computer", "computer_name")); user = normalize_identifier(_first(source, "user_id", "user", "username", "account", "actor")); session = normalize_identifier(_first(source, "session_id", "logon_id", "session", "logon_session")); pid_value = clean_text(_first(source, "pid", "process_id", "processId")); image = clean_text(_first(source, "image", "process_name", "executable", "process"))
    image_path = normalize_path(_first(source, "image_path", "executable_path", "path")) if event_type in {"process_start", "powershell_activity", "network_connection"} else None
    file_path_original = _first(source, "file_path", "path", "target_path", "image_path"); file_path = normalize_path(file_path_original) if event_type in {"file_create", "file_delete"} else None
    device_value = normalize_identifier(_first(source, "device_id", "volume_serial", "serial", "usb_id", "device")); ip_value = clean_text(_first(source, "ip", "remote_ip", "destination_ip", "src_ip", "dest_ip")); domain_value = normalize_identifier(_first(source, "domain", "remote_domain", "destination_domain"))
    entity_refs, entity_records = [], []
    def add(entity_id, entity_type, display_name, identifier, role): entity_refs.append({"entity_id": entity_id, "role": role}); entity_records.append((entity_id, entity_type, display_name, identifier))
    if host: add(f"host:{host}", "host", host, {"kind": "hostname", "value": host, "confidence": "high"}, "context")
    if user: add(_entity("user", user, host), "user", user, {"kind": "account", "value": user, "confidence": "medium"}, "actor")
    if session: add(_entity("session", session, host), "session", session, {"kind": "session_id", "value": session, "confidence": "high"}, "context")
    if pid_value or image:
        process_key = f"pid:{pid_value}" if pid_value else f"image:{normalize_identifier(image)}"; identifiers = ([{"kind": "pid", "value": pid_value, "scope": host, "confidence": "medium"}] if pid_value else [])
        if image: identifiers.append({"kind": "image", "value": image, "confidence": "medium"})
        add(_entity("process", process_key, host), "process", image or process_key, identifiers, "subject")
    if file_path: add(_entity("file", file_path, host), "file", str(file_path_original), {"kind": "path", "value": file_path, "confidence": "high"}, "object")
    if device_value: add(_entity("device", device_value, host), "device", device_value, {"kind": "device_id", "value": device_value, "confidence": "medium"}, "object")
    if ip_value: add(f"ip:{ip_value}", "ip", ip_value, {"kind": "ip", "value": ip_value, "confidence": "high"}, "object")
    if domain_value: add(f"domain:{domain_value}", "domain", domain_value, {"kind": "domain", "value": domain_value, "confidence": "high"}, "object")
    add(f"source:{file_id}", "source", source_path, {"kind": "file_id", "value": file_id, "confidence": "high"}, "source")
    attrs = {"pid": pid_value, "image": image, "image_path": image_path, "file_path": file_path, "file_path_original": clean_text(file_path_original), "command_line": clean_text(_first(source, "command_line", "cmdline", "command")), "parent_pid": clean_text(_first(source, "parent_pid", "parent_process_id", "parentPid", "creator_process_id")), "parent_process_guid": clean_text(_first(source, "parent_process_guid", "parent_guid", "parent_process_guid")), "process_guid": clean_text(_first(source, "process_guid", "guid", "process_guid")), "session_id": session, "device_id": device_value, "volume_serial": clean_text(_first(source, "volume_serial", "volume", "device_serial")), "mount_point": clean_text(_first(source, "mount_point", "drive", "mount")), "remote_ip": ip_value, "remote_domain": domain_value, "source_process_id": clean_text(_first(source, "source_process_id", "source_pid", "network_process_id")), "action": clean_text(_first(source, "action", "operation"))}
    provenance = {"source_file_id": file_id, "source_locator": locator, "parser": parser_name, "parser_version": parser_version, "import_batch_id": import_batch_id or stable_id("batch", file_id, length=16), "record_fingerprint": f"sha256:{fingerprint}"}
    if provenance_extra:
        provenance.update({str(key): value for key, value in provenance_extra.items() if value is not None})
    return {"schema_version": SCHEMA_VERSION, "event_id": stable_id("evt", file_id, locator, fingerprint, length=16), "event_type": event_type, "observed_at": observed_at, "host_id": f"host:{host}" if host else None, "entities": sorted(entity_refs, key=lambda x: (x["entity_id"], x["role"])), "attributes": {k: v for k, v in attrs.items() if v is not None}, "source_payload": source, "provenance": provenance, "_entity_records": entity_records}, warnings
