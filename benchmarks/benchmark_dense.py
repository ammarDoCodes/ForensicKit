"""Dense deterministic benchmark for relationships, threads, pivot, replay, and API bounds."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import threading
import time
import http.cookiejar
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from forensickit.adapters import parse_evidence
from forensickit.analysis import (
    _contradictions,
    _entities,
    _gaps,
    _relationships,
    _threads,
    analyze_case,
    pivot,
    replay,
    write_json,
    write_jsonl,
)
from forensickit.timeutil import timestamp_sort_key
from forensickit.auth import AuthManager
from forensickit.workbench import WorkbenchServer


EVENTS_PER_THREAD = 20


def _record(timestamp, event_type, host, user, session, **fields):
    return {"event_type": event_type, "timestamp": timestamp, "host": host, "user": user, "session_id": session, **fields}


def _write_fixture(evidence: Path, thread_count: int, events_per_thread: int) -> int:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    total = 0
    for thread_index in range(thread_count):
        host = f"dense-host-{thread_index:04d}"
        user = f"analyst-{thread_index:04d}"
        session = f"0x{thread_index + 1:04x}"
        child_pid = 20_000 + thread_index * 10
        parent_pid = child_pid - 1
        image_path = f"C:\\Users\\{user}\\Downloads\\payload-{thread_index:04d}.exe"
        records = [
            _record((start + timedelta(seconds=thread_index * 60)).isoformat().replace("+00:00", "Z"), "logon", host, user, session),
            _record((start + timedelta(seconds=thread_index * 60 + 1)).isoformat().replace("+00:00", "Z"), "device_connect", host, user, session, device_id=f"usb-{thread_index:04d}"),
            _record((start + timedelta(seconds=thread_index * 60 + 2)).isoformat().replace("+00:00", "Z"), "file_create", host, user, session, device_id=f"usb-{thread_index:04d}", file_path=image_path),
            _record((start + timedelta(seconds=thread_index * 60 + 3)).isoformat().replace("+00:00", "Z"), "process_start", host, user, session, pid=parent_pid, image="explorer.exe", image_path="C:\\Windows\\explorer.exe"),
            _record((start + timedelta(seconds=thread_index * 60 + 4)).isoformat().replace("+00:00", "Z"), "process_start", host, user, session, pid=child_pid, parent_pid=parent_pid, image=f"payload-{thread_index:04d}.exe", image_path=image_path),
            _record((start + timedelta(seconds=thread_index * 60 + 5)).isoformat().replace("+00:00", "Z"), "powershell_activity", host, user, session, pid=child_pid, parent_pid=parent_pid, image="powershell.exe", command_line="powershell.exe -NoProfile -Command Get-Process"),
            _record((start + timedelta(seconds=thread_index * 60 + 6)).isoformat().replace("+00:00", "Z"), "network_connection", host, user, session, pid=child_pid, remote_ip=f"198.51.100.{thread_index + 1}", remote_domain=f"dense-{thread_index:04d}.example.invalid"),
            _record((start + timedelta(seconds=thread_index * 60 + 7)).isoformat().replace("+00:00", "Z"), "file_delete", host, user, session, file_path=image_path),
        ]
        for offset in range(8, events_per_thread):
            event_time = start + timedelta(seconds=thread_index * 60 + offset)
            if offset % 2:
                records.append(_record(event_time.isoformat().replace("+00:00", "Z"), "network_connection", host, user, session, pid=child_pid, remote_ip=f"192.0.2.{thread_index + 1}"))
            else:
                records.append(_record(event_time.isoformat().replace("+00:00", "Z"), "file_create", host, user, session, file_path=f"C:\\Temp\\dense-{thread_index:04d}-{offset:02d}.tmp"))
        target = evidence / f"thread-{thread_index:04d}.jsonl"
        with target.open("w", encoding="utf-8", newline="\n") as output:
            for record in records:
                output.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        total += len(records)
    return total


def _api_call(opener, base_url: str, path: str) -> tuple[float, int]:
    started = time.perf_counter()
    with opener.open(base_url + path, timeout=30) as response:
        body = response.read()
    return time.perf_counter() - started, len(body)


def _authenticate_local(opener, base_url: str) -> None:
    payload = json.dumps({"username": "benchmark-user", "password": "benchmark-only-passphrase-2026"}).encode("utf-8")
    request = urllib.request.Request(
        base_url + "/api/auth/login",
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with opener.open(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError("The local benchmark profile could not authenticate.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark dense deterministic relationships, replay, pivot, and workbench API bounds")
    parser.add_argument("--threads", type=int, default=250)
    parser.add_argument("--events-per-thread", type=int, default=EVENTS_PER_THREAD)
    args = parser.parse_args()
    if args.threads <= 0 or args.events_per_thread < 8:
        raise SystemExit("threads must be positive and events-per-thread must be at least 8")

    base = ROOT / f"forensickit-dense-benchmark-{uuid.uuid4().hex}"
    base.mkdir(exist_ok=False)
    metrics = {"threads_requested": args.threads, "events_per_thread": args.events_per_thread}
    server = None
    server_thread = None
    try:
        evidence = base / "evidence"
        evidence.mkdir()
        metrics["event_count"] = _write_fixture(evidence, args.threads, args.events_per_thread)

        parse_started = time.perf_counter()
        parsed_events = []
        for source in sorted(evidence.glob("*.jsonl")):
            events, warnings = parse_evidence(source.read_bytes(), f"benchmark:{source.stem}", source.name, "jsonl-evidence", "benchmark-batch")
            parsed_events.extend(events)
        metrics["parse_seconds"] = time.perf_counter() - parse_started
        metrics["parsed_events"] = len(parsed_events)

        parsed_events.sort(key=lambda event: (timestamp_sort_key(event["observed_at"]), event["event_id"]))
        correlation_started = time.perf_counter()
        entities = _entities(parsed_events)
        relationships = _relationships(parsed_events)
        gaps = _gaps(parsed_events, relationships)
        contradictions = _contradictions(parsed_events, relationships)
        threads = _threads(parsed_events, relationships, gaps, contradictions)
        metrics["correlation_seconds"] = time.perf_counter() - correlation_started
        metrics.update({"entities": len(entities), "relationships": len(relationships), "gaps": len(gaps), "contradictions": len(contradictions), "candidate_threads": len(threads)})

        export_dir = base / "measured-export"
        export_dir.mkdir()
        export_started = time.perf_counter()
        write_jsonl(export_dir / "normalized-events.jsonl", parsed_events)
        write_json(export_dir / "entities.json", sorted(entities.values(), key=lambda value: value["entity_id"]))
        write_jsonl(export_dir / "relationships.jsonl", relationships)
        write_json(export_dir / "threads.json", threads)
        write_json(export_dir / "gaps.json", gaps)
        write_json(export_dir / "contradictions.json", contradictions)
        metrics["export_seconds"] = time.perf_counter() - export_started

        analysis_started = time.perf_counter()
        result = analyze_case(base / "case", evidence)
        metrics["full_analysis_seconds"] = time.perf_counter() - analysis_started
        process_entity = next(entity["entity_id"] for entity in result["entities"] if entity["type"] == "process")
        thread_id = result["threads"][0]["thread_id"]

        pivot_started = time.perf_counter()
        pivot_result = pivot(base / "case", process_entity, depth=1)
        metrics["pivot_seconds"] = time.perf_counter() - pivot_started
        metrics["pivot_events"] = len(pivot_result["events"])

        replay_started = time.perf_counter()
        replay_result = replay(base / "case", thread_id)
        metrics["replay_seconds"] = time.perf_counter() - replay_started
        metrics["replay_events"] = len(replay_result["events"])

        user_state = AuthManager(base / "benchmark-user-state")
        user_state.create_account(user_state.bootstrap_code or "", "benchmark-user", "benchmark-only-passphrase-2026")
        server = WorkbenchServer(("127.0.0.1", 0), base / "case", auth_manager=user_state)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        api_base = f"http://127.0.0.1:{server.server_port}"
        cookie_jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
        _authenticate_local(opener, api_base)
        case_id = result["manifest"]["case_id"]
        process_path = urllib.parse.quote(process_entity, safe="")
        thread_path = urllib.parse.quote(thread_id, safe="")
        api_calls = {
            "summary": f"/api/cases/{case_id}/summary",
            "timeline_bounded": f"/api/cases/{case_id}/events?limit=1000",
            "pivot_bounded": f"/api/cases/{case_id}/entities/{process_path}/pivot?depth=1&limit=1000",
            "replay_bounded": f"/api/cases/{case_id}/threads/{thread_path}?replay=1&limit=1000",
        }
        metrics["workbench_api_seconds"] = {}
        metrics["workbench_api_response_bytes"] = {}
        for name, path in api_calls.items():
            elapsed, size = _api_call(opener, api_base, path)
            metrics["workbench_api_seconds"][name] = elapsed
            metrics["workbench_api_response_bytes"][name] = size
        metrics["workbench_bind_address"] = server.server_address[0]
        metrics["workbench_result_limits"] = {"timeline": 2000, "pivot": 1000, "replay": 1000}
        metrics["within_60_seconds"] = metrics["full_analysis_seconds"] <= 60.0
        print(json.dumps({key: round(value, 6) if isinstance(value, float) else value for key, value in metrics.items()}, sort_keys=True))
        return 0 if metrics["within_60_seconds"] and len(result["threads"]) > 0 else 1
    finally:
        if server is not None:
            server.shutdown()
            if server_thread is not None:
                server_thread.join(timeout=5)
            server.server_close()
        if base.parent == ROOT and base.name.startswith("forensickit-dense-benchmark-"):
            shutil.rmtree(base)


if __name__ == "__main__":
    raise SystemExit(main())
