# ForensicKit

ForensicKit is a local-first digital-forensics investigation workbench. It imports bounded evidence without executing it, normalizes records into provenance-aware events, builds conservative relationships and candidate incident threads, and lets an analyst review timelines, pivots, replay, graphs, and reports. The core runs offline with Python's standard library; raw EVTX decoding is an optional extra.

This repository is the runnable source distribution. The sample evidence is synthetic. It is an investigation aid, **not** an automated finding of guilt, intent, or attribution. Preserve originals and independently validate conclusions before using them in a formal investigation.

## What is included

| Component | Purpose |
| --- | --- |
| `forensickit/` | Import limits, parsers, canonical model, correlation, investigation objects, report export, authenticated local workbench, and UI assets. |
| `schemas/` | Versioned data contracts. |
| `examples/sample-case/` | Synthetic evidence and a ready-to-open derived sample case. |
| `tests/` | Dependency-free regression, security, determinism, UI/API, report, and assistant tests. |
| `benchmarks/` | 100,000-event and dense relationship/thread performance checks. |
| `scripts/` and `start-workbench.cmd` | Windows source launcher, optional EVTX environment setup, and optional self-contained desktop-package builder. |

Supported inputs: JSONL, JSON arrays, CSV, Windows Event XML, Sysmon XML/JSON, bounded ZIP/TAR archives, and optionally binary `.evtx` through `python-evtx==0.8.1`. The EVTX adapter supports Security 4624/4625/4688, PowerShell 4103/4104, and Sysmon 1/3. Unsupported or malformed records produce diagnostics; they are not silently converted into facts.

## Quick start on Windows

Install Python 3.11 or newer, then open PowerShell **in this repository's root directory**. The commands use `py -3`, not the sometimes-missing `python` alias. No package install, account, cloud service, or third-party runtime dependency is needed for the sample case.

```powershell
py -3 --version
py -3 -m forensickit --version
py -3 tests/run_tests.py
py -3 -m forensickit summary examples/sample-case
py -3 -m forensickit serve examples/sample-case --port 8765
```

Open [http://127.0.0.1:8765/](http://127.0.0.1:8765/) in a browser. The terminal prints a one-time setup code for the first local account; keep it private. Create a username and password in the browser. Thereafter, sign in with that account. `Ctrl+C` stops the server. The workbench binds only to `127.0.0.1`; it is not designed to be internet-facing or shared across users.

From another working directory, run `start-workbench.cmd` or `scripts/start_workbench.ps1`; each locates its own checkout. If `py -3` is unavailable, set `FK_PYTHON` to an absolute Python 3.11+ executable for the command launcher, or pass `-PythonPath` to the PowerShell launcher. An existing Windows desktop package, if separately built, can use its bundled `runtime/python.exe`; this source repository does **not** ship CPython binaries.

```powershell
$env:FK_PYTHON = 'C:\path\to\python.exe'
.\start-workbench.cmd
# Alternatively:
.\scripts\start_workbench.ps1 -PythonPath 'C:\path\to\python.exe' -Port 8765
```

If you get `No module named forensickit`, check that the shell is in the cloned repository root (`Get-Location`, then `Get-ChildItem .\forensickit`) or use one of the launchers above. The directory containing the package must be the working directory unless you install it with `py -3 -m pip install -e .`.

## Analyze evidence

Create a **separate** case directory for derived files and point `--input` at a local evidence directory or supported archive. ForensicKit hashes source files and reads them without modifying them. Do not analyze into the source-evidence directory.

```powershell
New-Item -ItemType Directory -Path .\my-case -Force | Out-Null
py -3 -m forensickit analyze .\my-case --input .\examples\sample-case\evidence
py -3 -m forensickit summary .\my-case
py -3 -m forensickit threads .\my-case
py -3 -m forensickit serve .\my-case --port 8765
```

The resulting manifest, normalized events, entities, relationships, threads, gaps, contradictions, warnings, and analyst objects stay in the case directory. Source IDs, locators, hashes, parser versions, original timestamps, normalized UTC timestamps, uncertainty, and derivation-rule versions are retained. Correlation is conservative: time proximity alone is not proof, and uncertain entities are not silently merged. Repeating analysis of identical inputs produces the same canonical projection; analyst-authored objects are separate from evidence.

In the workbench, start at **Overview**, use **Timeline** filters, open a **Candidate Thread**, then **Replay** its sequence. Select an entity to **Pivot** or open the bounded **Graph**. The **Investigation** view records hypotheses, notes, and decisions without changing source evidence. The **Reports** view exports a reviewed scope. All evidence text and notes are treated as untrusted display data.

## Reports and assistant

Reports are deterministic for identical case data and settings. JSON, self-contained HTML, and Markdown are available. Raw evidence payloads are omitted by default; paths are redacted by default. Repeat `--redact` for `user`, `path`, `command_line`, `ip`, `domain`, `host`, `device`, or `text`. Redacted values are marked explicitly. HTML uses escaped content, a restrictive CSP, and no remote resources.

```powershell
py -3 -m forensickit export .\my-case --format json --output .\my-case\report.json
py -3 -m forensickit export .\my-case --format html --output .\my-case\report.html --redact user --redact ip
py -3 -m forensickit export .\my-case --format markdown --output .\my-case\report.md
```

The assistant is **disabled by default**. The deterministic fake provider is for local validation only, not substantive case reasoning. No external provider is bundled or contacted. Responses must cite available evidence; unsupported claims are rejected or marked insufficient.

```powershell
py -3 -m forensickit ask .\my-case --question 'Summarize this case' --task summarize_thread
py -3 -m forensickit ask .\my-case --question 'Summarize this case' --task summarize_thread --offline
```

## Raw EVTX: optional and partially validated

All non-EVTX workflows run without `python-evtx`. To isolate binary decoding, use the pinned optional dependency in a dedicated environment:

```powershell
.\scripts\create_evtx_env.ps1
# Or, in a separate Python environment:
py -3 -m pip install -e '.[evtx]'
py -3 -m forensickit analyze .\evtx-case --input .\approved-evidence --format evtx
```

If the dependency is absent, the adapter emits `OPTIONAL_DEPENDENCY_MISSING` rather than fabricating records. Binary-fixture validation is intentionally incomplete. Do not treat portable XML fixtures as proof that all binary Windows event families decode correctly. Private EVTX files must remain outside this repository.

**EVTX PARTIALLY VALIDATED — pending approved Windows Security and PowerShell binary fixtures**

The local-fixture validation command is `py -3 tests/run_evtx_integration.py --help`; supply only legally shareable or approved local fixtures as described by its arguments. No binary EVTX fixture is committed here.

## Verify the release

Run from the repository root. The test runner needs no pytest. Node.js is used only for JavaScript syntax verification; it is not a runtime dependency.

```powershell
py -3 tests/run_tests.py
py -3 -m compileall -q forensickit tests benchmarks
node --check forensickit/ui/app.js
py -3 -m forensickit analyze .\verification-case --input .\examples\sample-case\evidence
py -3 -m forensickit summary .\verification-case
py -3 benchmarks/benchmark_100k.py --count 100000
py -3 benchmarks/benchmark_dense.py --threads 250 --events-per-thread 20
```

Use a fresh, empty `verification-case` directory (or a new name each run); the analysis command writes derived case files there. Benchmark scripts create their own temporary benchmark directories. Tests cover archive traversal/bombs, linked paths, size bounds, malformed XML/encodings, injection text, provenance references, deterministic output, UI authentication/API bounds, report escaping/redaction, and assistant citation validation.

For an optional Windows desktop archive, `scripts/build_windows_release.ps1` requires an approved CPython **3.12** installation and the Windows .NET Framework compiler. It copies only runtime code, schemas, and the synthetic sample into the device package; it excludes tests, benchmarks, internal docs, build scripts, and agent material. The launcher is unsigned. Example:

```powershell
.\scripts\build_windows_release.ps1 -PythonRuntime 'C:\path\to\Python312\python.exe' -ReleaseDirectory 'C:\path\to\forensickit-windows-v1.2.3'
```

## Security and deployment boundaries

Imported files are data, never executed. Imports are read-only and bounded by size, count, depth, and compression ratio. The workbench serves a fixed local asset set with CSP and `nosniff`, checks Host/Origin, requires local authentication and CSRF protection for mutations, caps request and result sizes, and renders evidence text safely. Source evidence and derived analysis remain separate from analyst records. No telemetry, cloud service, external font/script, SQL database, payment integration, or hidden network provider is used.

This is a **single-user localhost investigation tool**, not a hardened multi-tenant web deployment. Keep case files and report exports in access-controlled storage; reports can still contain sensitive values unless you choose sufficient redaction. Do not expose port 8765 through a reverse proxy or public interface. Protect the local operating-system account. There is no code-signing certificate or installer in this repository.

## Known limitations

- Raw EVTX is only partially binary-validated as stated above; optional dependency and approved local fixtures are required for further sign-off.
- Candidate threads and relationships are evidence-guided leads, not causal or attribution proof. Data quality and missing logs constrain conclusions.
- Large timeline, graph, pivot, replay, and assistant responses are bounded and may be truncated; review warnings and narrow the scope.
- The local fake assistant is a test adapter, not an analytical model. External AI has not passed privacy review and is not enabled.
- A self-contained Windows executable must be built and validated separately; the source checkout alone requires Python 3.11+.
- No public software license is granted in this repository. Obtain permission before redistribution or reuse beyond applicable law.

See [CHANGELOG.md](CHANGELOG.md) for release history and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for optional/bundled-component notices.
