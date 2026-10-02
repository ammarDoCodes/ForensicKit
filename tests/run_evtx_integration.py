"""Validate the optional python-evtx decoder against approved local fixtures.

The default output is machine-readable JSON so this command can be used in a
release script. Pass ``--human`` for a concise review summary. The command
never copies a binary EVTX file into the repository and never emits raw event
content; fixture records contain only hashes, counts, and normalized status.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from forensickit.analysis import analyze_case  # noqa: E402
from forensickit.constants import PARSER_VERSIONS, SCHEMA_VERSION  # noqa: E402
from forensickit.evtx import (  # noqa: E402
    PARSER_NAME,
    PARSER_VERSION,
    SUPPORTED_EVENT_IDS,
    _load_evtx_class,
)
from forensickit.util import sha256_text  # noqa: E402


EXPECTED_EVENT_IDS = frozenset({"4624", "4625", "4688", "4103", "4104", "1", "3"})
EXPECTED_TYPES = {
    "4624": "logon",
    "4625": "logon_failure",
    "4688": "process_start",
    "4103": "powershell_activity",
    "4104": "powershell_activity",
    "1": "process_start",
    "3": "network_connection",
}

# These labels are deliberately narrower than the parser's supported-ID list.
# They are the release-validation units tracked by docs/20.
FAMILY_SPECS = {
    "sysmon-process": {"label": "Sysmon process creation", "event_ids": ("1",)},
    "sysmon-network": {"label": "Sysmon network", "event_ids": ("3",)},
    "windows-security-logon": {"label": "Windows Security logon", "event_ids": ("4624", "4625")},
    "windows-process": {"label": "Windows process creation", "event_ids": ("4688",)},
    "powershell": {"label": "PowerShell activity", "event_ids": ("4103", "4104")},
}
VALIDATION_MANIFEST = ROOT / "tests" / "fixtures" / "evtx" / "validation-manifest.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _projection(result: dict) -> dict:
    manifest = dict(result["manifest"])
    manifest.pop("created_at_utc", None)
    return {
        "manifest": manifest,
        "events": result["events"],
        "entities": result["entities"],
        "relationships": result["relationships"],
        "threads": result["threads"],
        "gaps": result["gaps"],
        "contradictions": result["contradictions"],
        "warnings": result["warnings"],
    }


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _validate_result(result: dict, fixture: Path, expected_hash: str) -> dict:
    inputs = result["manifest"].get("inputs", [])
    if len(inputs) != 1:
        raise AssertionError(f"expected one manifest input for {fixture.name}")
    manifest_input = inputs[0]
    if manifest_input.get("sha256") != expected_hash:
        raise AssertionError(f"manifest hash mismatch for {fixture.name}")
    if manifest_input.get("parser") != PARSER_NAME or manifest_input.get("parser_version") != PARSER_VERSION:
        raise AssertionError(f"manifest parser version mismatch for {fixture.name}")

    ids: set[str] = set()
    event_counts: dict[str, int] = {}
    for event in result["events"]:
        event_id = str(event.get("source_payload", {}).get("event_id", ""))
        ids.add(event_id)
        event_counts[event_id] = event_counts.get(event_id, 0) + 1
        provenance = event.get("provenance", {})
        required = {
            "source_file_id", "source_locator", "parser", "parser_version",
            "import_batch_id", "record_fingerprint", "source_file_sha256",
            "event_record_id", "provider", "channel",
        }
        missing = sorted(field for field in required if not provenance.get(field))
        if missing:
            raise AssertionError(f"missing provenance {missing} for {fixture.name} event {event.get('event_id')}")
        if provenance["parser"] != PARSER_NAME or provenance["parser_version"] != PARSER_VERSION:
            raise AssertionError(f"event parser version mismatch for {fixture.name}")
        if provenance["source_file_sha256"] != expected_hash:
            raise AssertionError(f"event source hash mismatch for {fixture.name}")
        if not str(provenance["source_locator"]).startswith("evtx-record["):
            raise AssertionError(f"invalid source locator for {fixture.name}")
        xml_record = event.get("source_payload", {}).get("xml_record")
        if not isinstance(xml_record, str):
            raise AssertionError(f"missing original XML record for {fixture.name}")
        if provenance["record_fingerprint"] != "sha256:" + sha256_text(xml_record):
            raise AssertionError(f"record fingerprint mismatch for {fixture.name}")
        observed_at = event.get("observed_at", {})
        if not observed_at.get("original") or not observed_at.get("utc"):
            raise AssertionError(f"missing original/UTC timestamp for {fixture.name}")
        if event.get("event_type") != EXPECTED_TYPES.get(event_id):
            raise AssertionError(f"unexpected canonical type for event {event_id} in {fixture.name}")

    unexpected = ids - EXPECTED_EVENT_IDS
    if unexpected:
        raise AssertionError(f"unsupported event IDs emitted by adapter: {sorted(unexpected)}")
    return {
        "event_counts": dict(sorted(event_counts.items())),
        "event_count": len(result["events"]),
        "warning_count": len(result["warnings"]),
        "case_id": result["manifest"]["case_id"],
    }


def _validate_fixture(fixture: Path) -> dict:
    fixture_hash = _sha256(fixture)
    work_root = ROOT / ".forensickit-evtx-integration-work"
    if work_root.exists():
        shutil.rmtree(work_root)
    work_root.mkdir()
    try:
        first = analyze_case(work_root / "first", fixture, format_hint="evtx")
        second = analyze_case(work_root / "second", fixture, format_hint="evtx")
        first_summary = _validate_result(first, fixture, fixture_hash)
        second_summary = _validate_result(second, fixture, fixture_hash)
        if _canonical_json(_projection(first)) != _canonical_json(_projection(second)):
            raise AssertionError(f"repeated binary EVTX analysis was not deterministic for {fixture.name}")
    finally:
        shutil.rmtree(work_root, ignore_errors=True)
    observed = set(first_summary["event_counts"])
    families = sorted(
        name for name, spec in FAMILY_SPECS.items()
        if set(spec["event_ids"]).issubset(observed)
    )
    return {
        "path_name": fixture.name,
        "sha256": fixture_hash,
        "deterministic": True,
        "families": families,
        **first_summary,
        "repeat_summary": second_summary,
    }


def _load_validation_manifest() -> dict:
    try:
        value = json.loads(VALIDATION_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"validation manifest unavailable: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("fixtures"), list):
        raise RuntimeError("validation manifest has an invalid shape")
    return value


def _selected_family_names(args: argparse.Namespace) -> list[str]:
    return list(args.family) if args.family else list(FAMILY_SPECS)


def _required_ids(args: argparse.Namespace) -> frozenset[str]:
    required = set(args.require_event_id or ())
    if args.family:
        for name in args.family:
            required.update(FAMILY_SPECS[name]["event_ids"])
    elif not required:
        required.update(EXPECTED_EVENT_IDS)
    return frozenset(required)


def _matrix(manifest: dict, selected_families: list[str]) -> list[dict]:
    rows = []
    fixtures = manifest.get("fixtures", [])
    for family in selected_families:
        spec = FAMILY_SPECS[family]
        matching = [
            fixture for fixture in fixtures
            if set(spec["event_ids"]).issubset(set(fixture.get("event_ids", [])))
            and fixture.get("validation_status") == "binary_validated_recorded"
        ]
        if matching:
            fixture = matching[0]
            rows.append({
                "family": family,
                "label": spec["label"],
                "event_ids": list(spec["event_ids"]),
                "parser_status": "implemented; canonical event mapping",
                "binary_decoder_status": "validated with python-evtx==0.8.1",
                "fixture_status": "recorded transient fixture; binary not retained",
                "fixture_label": fixture.get("label"),
                "fixture_sha256": fixture.get("sha256"),
                "provenance_status": "passed",
                "determinism_status": "passed",
                "security_status": "passed",
                "sign_off": "binary validated",
                "status": "passed",
                "next_action": "Keep the hash and repeat with an approved local fixture if redistribution is required.",
            })
        else:
            rows.append({
                "family": family,
                "label": spec["label"],
                "event_ids": list(spec["event_ids"]),
                "parser_status": "implemented; canonical event mapping",
                "binary_decoder_status": "available; binary family path not exercised",
                "fixture_status": "pending approved local binary fixture",
                "fixture_label": None,
                "fixture_sha256": None,
                "provenance_status": "portable/shim covered; binary assertions pending",
                "determinism_status": "portable/shim covered; binary comparison pending",
                "security_status": "bounded adapter checks covered; family fixture pending",
                "sign_off": "pending",
                "status": "pending",
                "next_action": f"Supply an approved binary fixture containing {', '.join(spec['event_ids'])} and run the strict integration command.",
            })
    return rows


def _status_payload(selected_families: list[str]) -> dict:
    manifest = _load_validation_manifest()
    matrix = _matrix(manifest, selected_families)
    validated = sum(row["sign_off"] == "binary validated" for row in matrix)
    release_status = "EVTX VALIDATED" if validated == len(matrix) else "EVTX PARTIALLY VALIDATED"
    skipped = [
        {
            "family": family,
            "label": FAMILY_SPECS[family]["label"],
            "event_ids": list(FAMILY_SPECS[family]["event_ids"]),
            "status": "skipped",
            "reason": "not selected by --family",
        }
        for family in FAMILY_SPECS
        if family not in selected_families
    ]
    return {
        "status": "passed" if release_status == "EVTX VALIDATED" else "pending",
        "release_status": release_status,
        "code": "EVTX_VALIDATION_STATUS",
        "schema_version": SCHEMA_VERSION,
        "parser": PARSER_NAME,
        "parser_version": PARSER_VERSION,
        "matrix": matrix,
        "skipped_families": skipped,
        "family_statuses": matrix + skipped,
        "validated_family_count": validated,
        "family_count": len(matrix),
        "fixture_manifest": manifest,
        "message": "Status is based on recorded validation metadata; live binary validation requires a supplied local fixture.",
    }


def _emit(payload: dict, human: bool) -> None:
    if not human:
        print(json.dumps(payload, ensure_ascii=True, sort_keys=True))
        return
    print(f"Release status: {payload.get('release_status', payload.get('status', 'unknown'))}")
    if payload.get("message"):
        print(payload["message"])
    for row in payload.get("matrix", []):
        print(f"- {row['label']} ({','.join(row['event_ids'])}): {row['status']} - {row['fixture_status']}")
    for row in payload.get("skipped_families", []):
        print(f"- {row['label']} ({','.join(row['event_ids'])}): skipped - {row['reason']}")
    for fixture in payload.get("fixtures", []):
        families = ", ".join(fixture.get("families", [])) or "no complete family"
        print(f"- {fixture['path_name']}: passed; {fixture['event_count']} events; families={families}; sha256={fixture['sha256']}")
    if payload.get("missing_event_ids"):
        print(f"Pending event IDs: {', '.join(payload['missing_event_ids'])}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate the actual optional python-evtx decoder against local binary EVTX files.")
    parser.add_argument("--fixture", action="append", type=Path, help="Local binary .evtx fixture; repeat for multiple logs. If omitted, FORENSICKIT_EVTX_FIXTURE may contain one or more os.pathsep-separated paths.")
    parser.add_argument("--family", action="append", choices=sorted(FAMILY_SPECS), help="Limit validation/status to a named event family; repeat for multiple families.")
    parser.add_argument("--require-event-id", action="append", choices=sorted(SUPPORTED_EVENT_IDS), help="Require this supported event ID across supplied fixtures; repeat for a subset of a local log.")
    parser.add_argument("--status-only", action="store_true", help="Report the recorded validation matrix without requiring the optional dependency or a local fixture.")
    parser.add_argument("--strict", action="store_true", help="Return pending (exit 2) unless every selected family/event ID is observed in the supplied fixtures.")
    parser.add_argument("--human", action="store_true", help="Print a concise human-readable summary instead of JSON.")
    parser.add_argument("--json", action="store_true", help="Explicitly select the default machine-readable JSON output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.status_only:
        try:
            payload = _status_payload(_selected_family_names(args))
        except RuntimeError as exc:
            payload = {"status": "blocked", "release_status": "EVTX VALIDATION BLOCKED", "code": "EVTX_STATUS_UNAVAILABLE", "message": str(exc)}
            _emit(payload, args.human)
            return 3
        _emit(payload, args.human)
        return 0

    fixtures = list(args.fixture or [])
    if not fixtures and os.environ.get("FORENSICKIT_EVTX_FIXTURE"):
        fixtures = [Path(value) for value in os.environ["FORENSICKIT_EVTX_FIXTURE"].split(os.pathsep) if value]
    if not fixtures:
        payload = {
            "status": "pending",
            "release_status": "EVTX PARTIALLY VALIDATED",
            "code": "EVTX_FIXTURE_REQUIRED",
            "message": "Supply --fixture PATH, FORENSICKIT_EVTX_FIXTURE, or use --status-only; no binary EVTX is committed.",
        }
        _emit(payload, args.human)
        return 2

    resolved = []
    invalid = []
    for fixture in fixtures:
        path = fixture.expanduser().resolve()
        if not path.is_file() or path.suffix.casefold() != ".evtx":
            invalid.append(str(path))
        else:
            resolved.append(path)
    if invalid:
        payload = {
            "status": "failed",
            "release_status": "EVTX VALIDATION FAILED",
            "code": "EVTX_FIXTURE_INVALID",
            "message": "Each fixture must be an existing .evtx file.",
            "invalid_fixtures": invalid,
        }
        _emit(payload, args.human)
        return 1

    decoder, dependency_status = _load_evtx_class()
    if decoder is None:
        payload = {
            "status": "blocked",
            "release_status": "EVTX VALIDATION BLOCKED",
            "code": "OPTIONAL_DEPENDENCY_MISSING",
            "message": "Install requirements-evtx.txt in the isolated EVTX environment before running binary validation.",
            "dependency_status": dependency_status,
            "parser_versions": PARSER_VERSIONS,
        }
        _emit(payload, args.human)
        return 3

    try:
        summaries = [_validate_fixture(path) for path in sorted(set(resolved), key=lambda item: str(item).casefold())]
    except (AssertionError, OSError, ValueError, RuntimeError) as exc:
        payload = {
            "status": "failed",
            "release_status": "EVTX VALIDATION FAILED",
            "code": "EVTX_INTEGRATION_FAILED",
            "message": str(exc),
            "parser_version": PARSER_VERSION,
        }
        _emit(payload, args.human)
        return 1

    required_ids = _required_ids(args)
    seen_ids = {event_id for summary in summaries for event_id in summary["event_counts"]}
    missing_ids = sorted(required_ids - seen_ids)
    if missing_ids:
        payload = {
            "status": "pending",
            "release_status": "EVTX PARTIALLY VALIDATED",
            "code": "EVTX_EVENT_FAMILIES_INCOMPLETE",
            "required_event_ids": sorted(required_ids),
            "missing_event_ids": missing_ids,
            "fixtures": summaries,
            "schema_version": SCHEMA_VERSION,
            "parser_version": PARSER_VERSION,
        }
        _emit(payload, args.human)
        return 2

    payload = {
        "status": "passed",
        "release_status": "EVTX VALIDATED",
        "schema_version": SCHEMA_VERSION,
        "parser": PARSER_NAME,
        "parser_version": PARSER_VERSION,
        "python_evtx_decoder": getattr(decoder, "__module__", "Evtx.Evtx"),
        "required_event_ids": sorted(required_ids),
        "supported_event_ids": sorted(EXPECTED_EVENT_IDS),
        "fixtures": summaries,
    }
    _emit(payload, args.human)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
