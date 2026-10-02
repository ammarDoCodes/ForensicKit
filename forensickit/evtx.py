"""Optional, bounded raw EVTX ingestion over the canonical event model."""

from __future__ import annotations

import importlib
import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from .constants import SCHEMA_VERSION
from .models import Diagnostic
from .parser import canonical_event
from .timeutil import timestamp_sort_key
from .util import clean_text, sha256_bytes, sha256_text, stable_json


PARSER_NAME = "evtx"
PARSER_VERSION = "1.1.0"
MAX_EVTX_FILE_BYTES = 50 * 1024 * 1024
MAX_EVTX_RECORD_COUNT = 250_000
MAX_EVTX_RECORD_BYTES = 2 * 1024 * 1024
SUPPORTED_EVENT_IDS = frozenset({"4624", "4625", "4688", "4103", "4104", "1", "3"})


def _diagnostic(code: str, message: str, file_id: str, locator: str) -> dict:
    return Diagnostic("warning", code, message, file_id, locator).as_dict()


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].casefold()


def _load_evtx_class():
    """Load python-evtx only when an EVTX input is actually parsed."""
    try:
        module = importlib.import_module("Evtx.Evtx")
        candidate = getattr(module, "Evtx", None)
        if callable(candidate):
            return candidate, None
        package = importlib.import_module("Evtx")
        candidate = getattr(package, "Evtx", None)
        if callable(candidate):
            return candidate, None
        return None, "invalid"
    except ModuleNotFoundError:
        return None, "missing"
    except ImportError:
        return None, "missing"
    except Exception:
        return None, "invalid"


def _record_value(record, *names):
    for name in names:
        value = getattr(record, name, None)
        if value is None:
            continue
        try:
            value = value() if callable(value) else value
        except Exception:
            continue
        if value not in (None, ""):
            return value
    return None


def _record_xml(record):
    value = _record_value(record, "xml", "to_xml")
    if isinstance(value, bytes):
        return value.decode("utf-8")
    if isinstance(value, str):
        return value
    raise ValueError("EVTX record did not provide XML text")


def _system_values(root: ET.Element) -> dict:
    system = next((node for node in root if _local(node.tag) == "system"), None)
    values: dict[str, object] = {}
    if system is None:
        return values
    for child in system:
        name = _local(child.tag)
        if name == "provider":
            values["provider"] = child.attrib.get("Name") or child.attrib.get("name")
        elif name == "eventid":
            values["event_id"] = clean_text(child.text)
        elif name == "timecreated":
            values["timestamp"] = child.attrib.get("SystemTime") or child.attrib.get("systemtime")
        elif name == "computer":
            values["host"] = clean_text(child.text)
        elif name == "eventrecordid":
            values["event_record_id"] = clean_text(child.text)
        elif name == "channel":
            values["channel"] = clean_text(child.text)
        elif name == "security":
            values["user"] = child.attrib.get("UserID") or child.attrib.get("userid")
        elif name == "execution":
            values["system_process_id"] = child.attrib.get("ProcessID") or child.attrib.get("processid")
    return values


def _event_data_values(root: ET.Element) -> dict:
    values: dict[str, object] = {}
    for node in root.iter():
        if _local(node.tag) != "data":
            continue
        name = node.attrib.get("Name") or node.attrib.get("name") or "value"
        value = "".join(node.itertext()).strip()
        if name in values:
            previous = values[name]
            values[name] = [previous, value] if not isinstance(previous, list) else previous + [value]
        else:
            values[name] = value
    return values


def _leaf_values(root: ET.Element) -> dict:
    values: dict[str, object] = {}
    for node in root.iter():
        if node is root or list(node):
            continue
        text = clean_text(node.text)
        if text:
            values.setdefault(_local(node.tag), text)
    return values


def _record_source(xml_text: str, event_record_id: object):
    from .adapters import _canonical_fields, _event_type

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return None, f"EVTX record XML is malformed: {exc}"
    system = _system_values(root)
    event_id = clean_text(system.get("event_id"))
    if not event_id:
        return None, "EVTX record has no EventID."
    if event_id not in SUPPORTED_EVENT_IDS:
        return {"_unsupported_event_id": event_id}, None
    record_id = clean_text(event_record_id) or clean_text(system.get("event_record_id"))
    source = {"xml_record": xml_text, **system, **_event_data_values(root)}
    for key, value in _leaf_values(root).items():
        source.setdefault(key, value)
    source["event_id"] = event_id
    if event_id in {"4624", "4625"}:
        source["user"] = source.get("TargetUserName") or source.get("SubjectUserName") or source.get("user")
        source["session_id"] = source.get("TargetLogonId") or source.get("SubjectLogonId") or source.get("session_id")
    elif event_id == "4688":
        source["user"] = source.get("SubjectUserName") or source.get("user")
        source["session_id"] = source.get("SubjectLogonId") or source.get("session_id")
        source["parent_pid"] = source.get("Creator_Process_Id") or source.get("CreatorProcessId") or source.get("parent_pid")
    source["event_type"] = _event_type(event_id, source.get("provider"), None)
    source["event_record_id"] = record_id
    source = _canonical_fields(source)
    source["event_id"] = event_id
    source["event_type"] = _event_type(event_id, source.get("provider"), None)
    return source, None


def _record_sort_key(event: dict):
    record_id = event.get("provenance", {}).get("event_record_id") or ""
    numeric = (0, int(record_id)) if str(record_id).isdigit() else (1, str(record_id))
    return (timestamp_sort_key(event.get("observed_at", {})), numeric, event.get("provenance", {}).get("source_locator", ""), event.get("event_id", ""))


def parse_evtx_xml_records(xml_records, file_id: str, source_path: str, import_batch_id: str, parser_version: str = PARSER_VERSION, source_file_sha256: str | None = None):
    """Parse XML records supplied by an EVTX decoder or a deterministic fixture."""
    events, diagnostics = [], []
    records = list(xml_records)
    if len(records) > MAX_EVTX_RECORD_COUNT:
        diagnostics.append(_diagnostic("RECORD_COUNT_LIMIT", f"Parsing stopped after {MAX_EVTX_RECORD_COUNT} EVTX records.", file_id, f"evtx-record[{MAX_EVTX_RECORD_COUNT + 1}]"))
        records = records[:MAX_EVTX_RECORD_COUNT]
    for number, item in enumerate(records, 1):
        if isinstance(item, tuple):
            xml_value, supplied_record_id = item[0], item[1] if len(item) > 1 else None
        else:
            xml_value, supplied_record_id = item, None
        locator_id = clean_text(supplied_record_id) or str(number)
        locator = f"evtx-record[{locator_id}]"
        if isinstance(xml_value, bytes):
            try:
                xml_text = xml_value.decode("utf-8")
            except UnicodeDecodeError:
                diagnostics.append(_diagnostic("INVALID_ENCODING", "EVTX record XML is not valid UTF-8.", file_id, locator))
                continue
        elif isinstance(xml_value, str):
            xml_text = xml_value
        else:
            diagnostics.append(_diagnostic("MALFORMED_EVTX_RECORD", "EVTX decoder returned a non-text record.", file_id, locator))
            continue
        if len(xml_text.encode("utf-8")) > MAX_EVTX_RECORD_BYTES:
            diagnostics.append(_diagnostic("EVTX_RECORD_TOO_LARGE", f"EVTX record exceeds {MAX_EVTX_RECORD_BYTES} byte limit.", file_id, locator))
            continue
        if re.search(r"<!\s*(doctype|entity)\b", xml_text, re.IGNORECASE):
            diagnostics.append(_diagnostic("XML_EXTERNAL_ENTITY_REJECTED", "EVTX record DTD or entity declarations are rejected.", file_id, locator))
            continue
        source, error = _record_source(xml_text, supplied_record_id)
        if error:
            diagnostics.append(_diagnostic("MALFORMED_EVTX_RECORD", error, file_id, locator))
            continue
        if source and source.get("_unsupported_event_id"):
            diagnostics.append(_diagnostic("UNSUPPORTED_EVTX_EVENT_ID", f"EVTX event ID {source['_unsupported_event_id']} is outside the supported event families.", file_id, locator))
            continue
        event_record_id = source.get("event_record_id")
        if event_record_id:
            locator = f"evtx-record[{event_record_id}]"
        event_type = source.get("event_type")
        if not source.get("provider"):
            diagnostics.append(_diagnostic("EVTX_MISSING_PROVIDER", "Supported EVTX record has no provider name.", file_id, locator))
        if not source.get("host"):
            diagnostics.append(_diagnostic("EVTX_MISSING_HOST", "Supported EVTX record has no computer/host field.", file_id, locator))
        event_id = str(source.get("event_id"))
        from .adapters import _canonical_fields
        normalized = _canonical_fields(source)
        if event_id in {"4624", "4625"} and not (normalized.get("user") or normalized.get("targetusername")):
            diagnostics.append(_diagnostic("EVTX_INCOMPLETE_LOGON", "Logon record has no target or subject user field.", file_id, locator))
        if event_id in {"4688", "1"} and not (normalized.get("pid") or normalized.get("image")):
            diagnostics.append(_diagnostic("EVTX_INCOMPLETE_PROCESS", "Process creation record has no process identifier or image.", file_id, locator))
        if event_id == "3" and not (normalized.get("remote_ip") or normalized.get("remote_domain")):
            diagnostics.append(_diagnostic("EVTX_INCOMPLETE_NETWORK", "Network record has no destination IP or domain.", file_id, locator))
        event, warnings = canonical_event(
            source,
            file_id,
            locator,
            source_path,
            sha256_text(xml_text),
            import_batch_id,
            PARSER_NAME,
            parser_version,
            {"event_record_id": event_record_id, "provider": source.get("provider"), "channel": source.get("channel"), "source_file_sha256": source_file_sha256},
        )
        events.append(event)
        diagnostics.extend(warnings)
    diagnostics.sort(key=stable_json)
    return sorted(events, key=_record_sort_key), diagnostics


def parse_evtx(raw: bytes, file_id: str, source_path: str, import_batch_id: str, _dependency_loader=None):
    """Decode raw EVTX through python-evtx without making it a core dependency."""
    if not isinstance(raw, (bytes, bytearray)):
        return [], [_diagnostic("MALFORMED_EVTX_INPUT", "EVTX input must be binary data.", file_id, "file")]
    if len(raw) > MAX_EVTX_FILE_BYTES:
        return [], [_diagnostic("EVTX_FILE_TOO_LARGE", f"EVTX file exceeds {MAX_EVTX_FILE_BYTES} byte limit.", file_id, "file")]
    if bytes(raw[:8]) != b"ElfFile\x00":
        return [], [_diagnostic("MALFORMED_EVTX_HEADER", "EVTX file signature is missing or invalid.", file_id, "file")]
    if _dependency_loader is None:
        decoder_class, dependency_status = _load_evtx_class()
    else:
        decoder_class = _dependency_loader()
        dependency_status = "missing" if decoder_class is None else None
    if decoder_class is None:
        if dependency_status == "invalid":
            return [], [_diagnostic("OPTIONAL_DEPENDENCY_INVALID", "The installed EVTX dependency could not provide a compatible decoder.", file_id, "file")]
        return [], [_diagnostic("OPTIONAL_DEPENDENCY_MISSING", "Raw EVTX parsing is unavailable. Install the optional dependency with the project EVTX extra.", file_id, "file")]
    temporary_path: Path | None = None
    events, diagnostics = [], []
    try:
        with tempfile.NamedTemporaryFile(prefix="forensickit-evtx-", suffix=".evtx", delete=False) as handle:
            handle.write(raw)
            temporary_path = Path(handle.name)
        log = decoder_class(str(temporary_path))
        entered = False
        reader = log
        try:
            enter = getattr(log, "__enter__", None)
            exit_context = getattr(log, "__exit__", None)
            if callable(enter) and callable(exit_context):
                reader = enter() or log
                entered = True
            records = []
            record_source = getattr(reader, "records", None)
            record_source = record_source() if callable(record_source) else record_source
            for number, record in enumerate(record_source or (), 1):
                if number > MAX_EVTX_RECORD_COUNT:
                    diagnostics.append(_diagnostic("RECORD_COUNT_LIMIT", f"Parsing stopped after {MAX_EVTX_RECORD_COUNT} EVTX records.", file_id, f"evtx-record[{number}]"))
                    break
                record_id = _record_value(record, "record_num", "record_id", "event_record_id")
                locator = f"evtx-record[{clean_text(record_id) or number}]"
                try:
                    xml_text = _record_xml(record)
                except UnicodeDecodeError:
                    diagnostics.append(_diagnostic("INVALID_ENCODING", "EVTX record XML is not valid UTF-8.", file_id, locator))
                    continue
                except Exception as exc:
                    diagnostics.append(_diagnostic("MALFORMED_EVTX_RECORD", f"EVTX record XML could not be read: {exc}.", file_id, locator))
                    continue
                if len(xml_text.encode("utf-8")) > MAX_EVTX_RECORD_BYTES:
                    diagnostics.append(_diagnostic("EVTX_RECORD_TOO_LARGE", f"EVTX record exceeds {MAX_EVTX_RECORD_BYTES} byte limit.", file_id, locator))
                    continue
                if re.search(r"<!\s*(doctype|entity)\b", xml_text, re.IGNORECASE):
                    diagnostics.append(_diagnostic("XML_EXTERNAL_ENTITY_REJECTED", "EVTX record DTD or entity declarations are rejected.", file_id, locator))
                    continue
                records.append((xml_text, record_id))
            parsed, parse_diagnostics = parse_evtx_xml_records(records, file_id, source_path, import_batch_id, PARSER_VERSION, sha256_bytes(bytes(raw)))
            events.extend(parsed)
            diagnostics.extend(parse_diagnostics)
        finally:
            if entered:
                log.__exit__(None, None, None)
            else:
                close = getattr(log, "close", None)
                if callable(close):
                    close()
    except (OSError, ValueError) as exc:
        diagnostics.append(_diagnostic("EVTX_READ_FAILED", f"EVTX decoder could not read the bounded input: {exc}.", file_id, "file"))
    except Exception:
        diagnostics.append(_diagnostic("EVTX_READ_FAILED", "EVTX decoder failed while reading the bounded input.", file_id, "file"))
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                diagnostics.append(_diagnostic("TEMPORARY_FILE_CLEANUP_FAILED", "Temporary EVTX staging file could not be removed.", file_id, "file"))
    diagnostics.sort(key=stable_json)
    return sorted(events, key=_record_sort_key), diagnostics
