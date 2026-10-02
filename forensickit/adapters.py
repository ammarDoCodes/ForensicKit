from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET

from .constants import SCHEMA_VERSION
from .models import Diagnostic
from .parser import MAX_RECORD_COUNT, canonical_event, parse_jsonl
from .util import clean_text, sha256_text, stable_json


EVENT_ID_MAP = {
    "4624": "logon", "4625": "logon_failure", "4688": "process_start", "4103": "powershell_activity", "4104": "powershell_activity", "400": "powershell_activity", "403": "powershell_activity", "5156": "network_connection",
    "1": "process_start", "3": "network_connection", "11": "file_create", "12": "file_create", "13": "file_create", "22": "network_connection",
}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].casefold()


def _event_type(event_id: object, provider: object = None, existing: object = None) -> str:
    if existing:
        return str(existing)
    event_id_text = clean_text(event_id)
    provider_text = (clean_text(provider) or "").casefold()
    if event_id_text in EVENT_ID_MAP:
        if provider_text == "sysmon" or event_id_text in {"1", "3", "11", "12", "13", "22"}:
            return EVENT_ID_MAP[event_id_text]
        return EVENT_ID_MAP[event_id_text]
    return "unknown"


def _canonical_fields(source: dict) -> dict:
    values = {str(key).casefold().replace(" ", "_"): value for key, value in source.items()}
    def first(*keys):
        for key in keys:
            if key in values and values[key] not in (None, ""):
                return values[key]
        return None
    event_id = first("event_id", "eventid", "id")
    output = dict(source)
    output["event_type"] = _event_type(event_id, first("provider", "provider_name", "source"), first("event_type", "type", "kind"))
    mappings = {
        "timestamp": ("timestamp", "time", "datetime", "utctime", "utc_time", "timecreated", "created_at"),
        "host": ("host", "hostname", "computer", "computer_name"),
        "user": ("user", "username", "targetusername", "target_user_name", "subjectusername", "subject_user_name", "account"),
        "session_id": ("session_id", "logonid", "logon_id", "targetlogonid", "target_logon_id", "subjectlogonid", "subject_logon_id", "session"),
        "pid": ("pid", "processid", "process_id", "newprocessid", "new_process_id", "sourceprocessid", "source_process_id"),
        "parent_pid": ("parentpid", "parent_pid", "parentprocessid", "creatorprocessid", "creator_process_id"),
        "process_guid": ("processguid", "process_guid", "guid"),
        "parent_process_guid": ("parentprocessguid", "parent_process_guid", "parentguid"),
        "image": ("image", "process_name", "processname", "newprocessname", "new_process_name", "sourceimage", "executable"),
        "image_path": ("imagepath", "image_path", "executable_path"),
        "command_line": ("commandline", "command_line", "cmdline", "command"),
        "file_path": ("filepath", "file_path", "targetfilename", "target_filename", "path"),
        "device_id": ("deviceid", "device_id", "serial", "usb_id", "volume_serial", "volumeserialnumber"),
        "volume_serial": ("volume_serial", "volumeserialnumber", "serial"),
        "mount_point": ("mount_point", "drive", "mount"),
        "remote_ip": ("destinationip", "destination_ip", "remote_ip", "dest_ip", "ip"),
        "remote_domain": ("destinationhostname", "destination_hostname", "remote_domain", "domain"),
        "source_process_id": ("sourceprocessid", "source_process_id", "network_process_id"),
        "action": ("action", "operation"),
    }
    for target, keys in mappings.items():
        value = first(*keys)
        if value is not None:
            output[target] = value
    return output


def parse_json_array(raw: bytes, file_id: str, source_path: str, import_batch_id: str, parser_name: str = "json-array-evidence", parser_version: str = "1.0.0"):
    try:
        value = json.loads(raw.decode("utf-8-sig"))
    except UnicodeDecodeError:
        return [], [Diagnostic("warning", "INVALID_ENCODING", "File is not valid UTF-8.", file_id, "file").as_dict()]
    except json.JSONDecodeError as exc:
        return [], [Diagnostic("warning", "MALFORMED_JSON", f"JSON document is malformed: {exc.msg}.", file_id, "file").as_dict()]
    if isinstance(value, dict) and isinstance(value.get("events"), list):
        value = value["events"]
    elif isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        return [], [Diagnostic("warning", "JSON_ARRAY_REQUIRED", "JSON adapter requires an array or an object containing an events array.", file_id, "file").as_dict()]
    events, diagnostics = [], []
    if len(value) > MAX_RECORD_COUNT:
        diagnostics.append(Diagnostic("warning", "RECORD_COUNT_LIMIT", f"Parsing stopped after {MAX_RECORD_COUNT} records.", file_id, f"record[{MAX_RECORD_COUNT + 1}]").as_dict())
        value = value[:MAX_RECORD_COUNT]
    for number, item in enumerate(value, 1):
        locator = f"record[{number}]"
        if not isinstance(item, dict):
            diagnostics.append(Diagnostic("warning", "RECORD_NOT_OBJECT", "JSON array member must be an object.", file_id, locator).as_dict())
            continue
        source = _canonical_fields(item)
        event, warnings = canonical_event(source, file_id, locator, source_path, sha256_text(stable_json(item)), import_batch_id, parser_name, parser_version)
        events.append(event)
        diagnostics.extend(warnings)
    return events, diagnostics


def parse_csv(raw: bytes, file_id: str, source_path: str, import_batch_id: str, parser_version: str = "1.0.0"):
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return [], [Diagnostic("warning", "INVALID_ENCODING", "File is not valid UTF-8.", file_id, "file").as_dict()]
    try:
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            return [], [Diagnostic("warning", "CSV_HEADER_MISSING", "CSV file has no header row.", file_id, "file").as_dict()]
        events, diagnostics = [], []
        for number, row in enumerate(reader, 2):
            if number - 1 > MAX_RECORD_COUNT:
                diagnostics.append(Diagnostic("warning", "RECORD_COUNT_LIMIT", f"Parsing stopped after {MAX_RECORD_COUNT} records.", file_id, f"row[{number}]").as_dict())
                break
            source = _canonical_fields(dict(row))
            event, warnings = canonical_event(source, file_id, f"row[{number}]", source_path, sha256_text(stable_json(dict(row))), import_batch_id, "csv-evidence", parser_version)
            events.append(event)
            diagnostics.extend(warnings)
        return events, diagnostics
    except csv.Error as exc:
        return [], [Diagnostic("warning", "MALFORMED_CSV", f"CSV record is malformed: {exc}.", file_id, "file").as_dict()]


def _xml_source(element: ET.Element, raw_xml: str, sysmon: bool) -> dict:
    source: dict[str, object] = {"xml_record": raw_xml}
    system = next((child for child in element if _local(child.tag) == "system"), None)
    event_id = None
    if system is not None:
        for child in system:
            key = _local(child.tag)
            if key == "eventid": event_id = child.text
            elif key == "timecreated": source["timestamp"] = child.attrib.get("SystemTime") or child.attrib.get("systemtime")
            elif key == "computer": source["host"] = child.text
            elif key == "security": source["user"] = child.attrib.get("UserID") or child.attrib.get("userid")
            elif key == "execution": source["pid"] = child.attrib.get("ProcessID") or child.attrib.get("processid")
    data = {}
    for node in element.iter():
        if _local(node.tag) == "data":
            name = node.attrib.get("Name") or node.attrib.get("name") or "value"
            data[name] = node.text or ""
    source.update(data)
    source.update(_canonical_fields(source))
    source["event_id"] = event_id
    source["event_type"] = _event_type(event_id, "Sysmon" if sysmon else "Windows", None)
    return source


def parse_xml(raw: bytes, file_id: str, source_path: str, import_batch_id: str, parser_name: str, parser_version: str = "1.0.0"):
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return [], [Diagnostic("warning", "INVALID_ENCODING", "XML file is not valid UTF-8.", file_id, "file").as_dict()]
    if re.search(r"<!\s*(doctype|entity)\b", text, re.IGNORECASE):
        return [], [Diagnostic("warning", "XML_EXTERNAL_ENTITY_REJECTED", "XML DTD or entity declarations are rejected; external resolution is disabled.", file_id, "file").as_dict()]
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return [], [Diagnostic("warning", "MALFORMED_XML", f"XML document is malformed: {exc}.", file_id, "file").as_dict()]
    nodes = [root] if _local(root.tag) == "event" else [node for node in root.iter() if _local(node.tag) == "event"]
    if not nodes:
        return [], [Diagnostic("warning", "XML_NO_EVENTS", "XML document contains no Event elements.", file_id, "file").as_dict()]
    events, diagnostics = [], []
    if len(nodes) > MAX_RECORD_COUNT:
        diagnostics.append(Diagnostic("warning", "RECORD_COUNT_LIMIT", f"Parsing stopped after {MAX_RECORD_COUNT} records.", file_id, f"xml-event[{MAX_RECORD_COUNT + 1}]").as_dict())
        nodes = nodes[:MAX_RECORD_COUNT]
    sysmon = parser_name == "sysmon-xml"
    for number, node in enumerate(nodes, 1):
        xml_record = ET.tostring(node, encoding="unicode")
        source = _xml_source(node, xml_record, sysmon)
        event, warnings = canonical_event(source, file_id, f"xml-event[{number}]", source_path, sha256_text(xml_record), import_batch_id, parser_name, parser_version)
        events.append(event)
        diagnostics.extend(warnings)
    return events, diagnostics


def parse_evidence(raw: bytes, file_id: str, source_path: str, detected_format: str, import_batch_id: str):
    if detected_format == "jsonl-evidence":
        return parse_jsonl(raw, file_id, source_path, import_batch_id)
    if detected_format == "json-array-evidence":
        return parse_json_array(raw, file_id, source_path, import_batch_id)
    if detected_format == "sysmon-json":
        return parse_json_array(raw, file_id, source_path, import_batch_id, "sysmon-json")
    if detected_format == "csv-evidence":
        return parse_csv(raw, file_id, source_path, import_batch_id)
    if detected_format in {"windows-event-xml", "sysmon-xml"}:
        return parse_xml(raw, file_id, source_path, import_batch_id, detected_format)
    if detected_format == "evtx":
        from .evtx import parse_evtx
        return parse_evtx(raw, file_id, source_path, import_batch_id)
    return [], [Diagnostic("warning", "UNSUPPORTED_FORMAT", f"No parser is available for {source_path}.", file_id, "file").as_dict()]
