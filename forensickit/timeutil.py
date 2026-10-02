from __future__ import annotations
from datetime import date, datetime, timezone
from typing import Any

def normalize_timestamp(value: Any) -> tuple[dict, str | None]:
    original = None if value is None else str(value)
    if original is None or not original.strip(): return {"original": original, "utc": None, "precision": "unknown", "quality": "unknown", "timezone_source": "missing"}, "MISSING_TIMESTAMP"
    text, parsed = original.strip(), None; precision, quality, timezone_source = "second", "exact", "record-offset"
    try:
        if text.isdigit(): parsed = datetime.fromtimestamp(int(text), tz=timezone.utc); quality, timezone_source = "inferred", "unix-epoch"
        else:
            candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
            if len(candidate) == 10 and candidate[4] == "-" and candidate[7] == "-": parsed = datetime.combine(date.fromisoformat(candidate), datetime.min.time()); precision, quality, timezone_source = "date", "inferred", "assumed-utc"
            else:
                parsed = datetime.fromisoformat(candidate)
                if parsed.tzinfo is None: parsed = parsed.replace(tzinfo=timezone.utc); quality, timezone_source = "inferred", "assumed-utc"
    except (ValueError, OverflowError, OSError): return {"original": original, "utc": None, "precision": "unknown", "quality": "unknown", "timezone_source": "unparseable"}, "INVALID_TIMESTAMP"
    return {"original": original, "utc": parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), "precision": precision, "quality": quality, "timezone_source": timezone_source}, None
def timestamp_sort_key(observed: dict) -> tuple: return (observed.get("utc") or "", {"exact": 0, "inferred": 1, "unknown": 2}.get(observed.get("quality"), 9))

