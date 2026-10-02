# EVTX adapter fixtures

These are portable XML event records, not copied Windows log files. They are
used to exercise the raw EVTX decoder boundary without making the default test
runner depend on `python-evtx` or on a legally shareable binary event log.

`tests/test_evtx.py` supplies a small decoder shim that presents these records
through the same `records()`/`xml()` interface used by the optional decoder.
