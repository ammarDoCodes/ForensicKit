from forensickit.timeutil import normalize_timestamp
def test_offset_is_preserved_and_normalized():
    value, warning = normalize_timestamp("2026-09-21T09:41:00-07:00")
    assert warning is None; assert value["original"].endswith("-07:00"); assert value["utc"] == "2026-09-21T16:41:00Z"; assert value["quality"] == "exact"
def test_missing_time_is_explicit():
    value, warning = normalize_timestamp(None)
    assert warning == "MISSING_TIMESTAMP"; assert value["quality"] == "unknown"; assert value["utc"] is None
