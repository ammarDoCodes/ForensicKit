"""Tests for the binary-EVTX release-validation harness itself."""

from __future__ import annotations

import contextlib
import io
import json
from unittest.mock import patch

import run_evtx_integration as runner


def _run(args: list[str]) -> tuple[int, dict, str]:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = runner.main(args)
    text = output.getvalue().strip()
    return code, json.loads(text), text


def test_evtx_status_matrix_is_explicit_and_partial() -> None:
    code, payload, _ = _run(["--status-only"])
    assert code == 0
    assert payload["release_status"] == "EVTX PARTIALLY VALIDATED"
    assert payload["validated_family_count"] == 2
    assert payload["family_count"] == 5
    rows = {row["family"]: row for row in payload["matrix"]}
    assert rows["sysmon-process"]["sign_off"] == "binary validated"
    assert rows["sysmon-network"]["sign_off"] == "binary validated"
    assert rows["windows-security-logon"]["sign_off"] == "pending"
    assert rows["powershell"]["fixture_sha256"] is None
    assert payload["fixture_manifest"]["fixtures"][0]["committed"] is False


def test_evtx_status_only_can_scope_a_family_and_human_output() -> None:
    code, payload, _ = _run(["--status-only", "--family", "sysmon-process"])
    assert code == 0
    assert payload["release_status"] == "EVTX VALIDATED"
    assert payload["matrix"][0]["event_ids"] == ["1"]
    assert {row["status"] for row in payload["skipped_families"]} == {"skipped"}

    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert runner.main(["--status-only", "--human"]) == 0
    assert "Release status: EVTX PARTIALLY VALIDATED" in output.getvalue()
    assert "Windows Security logon" in output.getvalue()


def test_evtx_fixture_exit_contract_for_missing_and_invalid_inputs() -> None:
    code, payload, _ = _run(["--strict", "--family", "powershell"])
    assert code == 2
    assert payload["code"] == "EVTX_FIXTURE_REQUIRED"

    missing = runner.ROOT / ".definitely-missing-evtx-fixture.evtx"
    code, payload, _ = _run(["--fixture", str(missing)])
    assert code == 1
    assert payload["status"] == "failed"
    assert payload["code"] == "EVTX_FIXTURE_INVALID"


def test_evtx_runner_reports_optional_dependency_as_blocked() -> None:
    fixture = runner.ROOT / ".runner-dependency-check.evtx"
    fixture.write_bytes(b"ElfFile\x00")
    try:
        with patch.object(runner, "_load_evtx_class", return_value=(None, "python-evtx not installed")):
            code, payload, _ = _run(["--fixture", str(fixture)])
    finally:
        fixture.unlink(missing_ok=True)
    assert code == 3
    assert payload["status"] == "blocked"
    assert payload["code"] == "OPTIONAL_DEPENDENCY_MISSING"
