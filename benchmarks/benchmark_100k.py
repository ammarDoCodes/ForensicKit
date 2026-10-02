from __future__ import annotations

import argparse
import json
import shutil
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from forensickit.analysis import analyze_case


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark deterministic analysis of normalized events")
    parser.add_argument("--count", type=int, default=100_000)
    args = parser.parse_args()
    root = ROOT
    started = time.perf_counter()
    base = root / ".forensickit-benchmark"
    if base.exists():
        shutil.rmtree(base)
    base.mkdir()
    try:
        evidence = base / "evidence"
        evidence.mkdir()
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with (evidence / "events.jsonl").open("w", encoding="utf-8", newline="\n") as output:
            for index in range(args.count):
                timestamp = (start + timedelta(seconds=index)).isoformat().replace("+00:00", "Z")
                output.write(json.dumps({"event_type": "logon", "timestamp": timestamp}, sort_keys=True, separators=(",", ":")) + "\n")
        result = analyze_case(base / "case", evidence)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    elapsed = time.perf_counter() - started
    print(json.dumps({"event_count": args.count, "parsed_events": len(result["events"]), "relationships": len(result["relationships"]), "threads": len(result["threads"]), "elapsed_seconds": round(elapsed, 3), "within_60_seconds": elapsed <= 60.0}, sort_keys=True))
    return 0 if len(result["events"]) == args.count and elapsed <= 60.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
