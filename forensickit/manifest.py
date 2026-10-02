from __future__ import annotations
from datetime import datetime, timezone
import json
import csv
import io
from pathlib import Path
from .constants import DERIVED_FILES, PARSER_NAME, PARSER_VERSION, PARSER_VERSIONS, SCHEMA_VERSION
from .util import is_reparse_point, sha256_bytes, safe_relative_path, stable_id, stable_json
MAX_FILE_COUNT, MAX_FILE_BYTES, MAX_TOTAL_BYTES = 1000, 50 * 1024 * 1024, 200 * 1024 * 1024

def detect_format(raw: bytes, suffix: str, format_hint: str | None = None) -> str:
    """Detect the supported fixture format from content, with suffix as a hint only."""
    if format_hint == "evtx" or suffix.casefold() == ".evtx" or raw[:8] == b"ElfFile\x00":
        return "evtx"
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return "unsupported"
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    if first.startswith("<"):
        return "sysmon-xml" if "sysmon" in text[:4096].casefold() else "windows-event-xml"
    if suffix.casefold() == ".csv":
        try:
            if len(list(csv.reader(io.StringIO(text)))) >= 1:
                return "csv-evidence"
        except csv.Error:
            return "csv-evidence"
    if first.startswith("["):
        try:
            value = json.loads(text)
            if isinstance(value, list):
                return "json-array-evidence"
        except json.JSONDecodeError:
            return "json-array-evidence" if suffix.casefold() == ".json" else "unsupported"
    if first.startswith("{"):
        try:
            value = json.loads(text) if suffix.casefold() == ".json" else json.loads(first)
            if isinstance(value, list):
                return "json-array-evidence"
            if isinstance(value, dict):
                if any(key.casefold() in {"eventid", "event_id", "sysmon"} for key in value):
                    return "sysmon-json"
                return "json-array-evidence" if suffix.casefold() == ".json" else "jsonl-evidence"
        except json.JSONDecodeError:
            # A malformed first record is still a JSONL candidate if the extension is explicit.
            if suffix.casefold() in {".jsonl", ".ndjson"}:
                return "jsonl-evidence"
    return "unsupported"

def discover_inputs(input_path: Path, case_dir: Path):
    if input_path.is_symlink() or (input_path.exists() and is_reparse_point(input_path)):
        raise ValueError("symbolic-link or reparse-point import roots are not allowed")
    input_path, case_dir = input_path.resolve(), case_dir.resolve()
    if not input_path.exists(): raise ValueError(f"input path does not exist: {input_path}")
    if input_path.is_symlink() or is_reparse_point(input_path): raise ValueError("symbolic-link or reparse-point import roots are not allowed")
    candidates = [input_path] if input_path.is_file() else sorted(input_path.rglob("*"), key=lambda p: p.as_posix().casefold())
    files, diagnostics, total = [], [], 0
    for candidate in candidates:
        if candidate.is_symlink() or is_reparse_point(candidate):
            diagnostics.append({"schema_version": SCHEMA_VERSION, "severity": "warning", "code": "LINK_OR_REPARSE_REJECTED", "message": "Symbolic-link or reparse-point input was rejected.", "path": str(candidate)})
            continue
        if not candidate.is_file():
            continue
        if input_path.is_dir() and candidate.name in DERIVED_FILES and candidate.parent == case_dir: continue
        size = candidate.stat().st_size
        if size > MAX_FILE_BYTES: diagnostics.append({"schema_version": SCHEMA_VERSION, "severity": "warning", "code": "FILE_TOO_LARGE", "message": f"File exceeds {MAX_FILE_BYTES} byte limit.", "path": str(candidate)}); continue
        if total + size > MAX_TOTAL_BYTES: diagnostics.append({"schema_version": SCHEMA_VERSION, "severity": "warning", "code": "IMPORT_TOTAL_TOO_LARGE", "message": f"Import exceeds {MAX_TOTAL_BYTES} byte limit."}); break
        files.append(candidate); total += size
        if len(files) >= MAX_FILE_COUNT: diagnostics.append({"schema_version": SCHEMA_VERSION, "severity": "warning", "code": "FILE_COUNT_LIMIT", "message": f"Only the first {MAX_FILE_COUNT} files were inspected."}); break
    return files, diagnostics
def build_manifest(case_dir: Path, input_root: Path, files: list[Path], existing=None, archive_info=None, format_hint: str | None = None):
    base = input_root.parent if input_root.is_file() else input_root; inputs, contents = [], {}
    for path in sorted(files, key=lambda p: p.as_posix().casefold()):
        raw = path.read_bytes(); file_hash = sha256_bytes(raw); file_id = stable_id("file", file_hash, length=16)
        detected = detect_format(raw, path.suffix, format_hint if input_root.is_file() or path.suffix.casefold() == ".evtx" else None)
        parser_name = detected if detected in PARSER_VERSIONS else None
        inputs.append({"file_id": file_id, "relative_path": safe_relative_path(base, path), "size_bytes": len(raw), "sha256": file_hash, "detected_format": detected, "parser": parser_name, "parser_version": PARSER_VERSIONS.get(parser_name) if parser_name else None}); contents[file_id] = raw
    config = {"schema_version": SCHEMA_VERSION, "parser_versions": PARSER_VERSIONS, "rule_versions": {"core-correlation": "1.0.0"}}
    case_id = stable_id("case", *[(i["relative_path"], i["sha256"]) for i in inputs], length=12)
    config_hash = "sha256:" + sha256_bytes(stable_json(config).encode())
    import_batch_id = stable_id("batch", case_id, config_hash, length=16)
    manifest = {"schema_version": SCHEMA_VERSION, "case_id": case_id, "created_at_utc": (existing or {}).get("created_at_utc", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")), "import_batch_id": import_batch_id, "analysis_config_hash": config_hash, "inputs": inputs}
    if archive_info:
        manifest["archive"] = archive_info
    return manifest, contents
