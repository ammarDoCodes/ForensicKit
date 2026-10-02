# Changelog

This changelog describes shipped capabilities, not claims of forensic validation. Analysis contracts retain their own schema, parser, and correlation-rule versions.

## 1.2.3 — Curated source release and security stabilization

- Published the runnable offline project with a self-contained setup and investigation guide; excluded internal agent instructions, design specifications, architecture drafts, private evidence, and generated artifacts from the public distribution.
- Prevented analysis from writing through linked case/input roots or derived-output hardlink/reparse collisions with source files.
- Made archive-import scratch space unique and stopped cleanup from touching a pre-existing sibling folder.
- Hardened unsupported HTTP-method responses with generic JSON, security headers, and no Python runtime banner.
- Added regression coverage for those cases and kept the Windows device-package builder limited to runtime files, schemas, and synthetic sample data.

## 1.2.2 — Local workbench and report review

- Added first-run local account setup, session/CSRF protections, appearance controls, responsive navigation, and local report downloads to the workbench.
- Added deterministic JSON, self-contained HTML, and Markdown reports with scope selection, provenance, bounded graph inclusion, raw-payload omission, and configurable redaction.
- Added an optional evidence-grounded assistant boundary: disabled by default, deterministic fake provider for tests, bounded context, citation validation, prompt-injection checks, and sensitive-payload-free audit logging. No external provider is bundled.
- Added a Windows desktop launcher and portable-package builder; generated executables remain unsigned and require separate build validation.

## 1.1.0 — Post-v1 adapters and investigation views

- Added bounded evidence-graph visualization and Windows Event XML, Sysmon XML/JSON, CSV, JSON-array, and optional raw EVTX adapters.
- Added parent/child process, device/file, and process/network correlation where explicit evidence supports a relationship.
- Added hypotheses, analyst notes, decisions, deeper pivots, replay explanations, contradictions, gaps, and uncertainty indicators.
- Isolated raw EVTX behind optional `python-evtx==0.8.1`; binary validation is incomplete.

## 1.0.0 — Initial forensic reconstruction slice

- Added safe local import, canonical events with original and UTC timestamps, source hashes and locators, deterministic relationship/thread generation, warnings, and versioned schemas.
- Added a local-first investigation workbench, standard-library tests, synthetic sample case, and performance benchmarks.

**Current EVTX status:** EVTX PARTIALLY VALIDATED — pending approved Windows Security and PowerShell binary fixtures
