from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from . import __version__
from .analysis import analyze_case, load_case, pivot, replay
from .assistant import ALLOWED_TASKS, AssistantError, ask_assistant
from .investigation import create_decision, create_hypothesis, create_note, list_investigation, update_hypothesis
from .report import build_report, export_report, render_json
def _dump(v, machine=False): print(json.dumps(v, ensure_ascii=True, sort_keys=True, indent=None if machine else 2))
def build_parser():
    p = argparse.ArgumentParser(prog="forensickit", description="Offline, provenance-preserving forensic reconstruction"); s = p.add_subparsers(dest="command", required=True)
    p.add_argument("--version", action="version", version=__version__)
    a = s.add_parser("analyze"); a.add_argument("case_dir", type=Path); a.add_argument("--input", required=True, type=Path); a.add_argument("--format", choices=("auto", "evtx"), default="auto", help="Override format detection for an EVTX input."); a.add_argument("--json", action="store_true")
    for name in ("summary", "threads"):
        q = s.add_parser(name); q.add_argument("case_dir", type=Path); q.add_argument("--json", action="store_true")
    q = s.add_parser("thread"); q.add_argument("case_dir", type=Path); q.add_argument("thread_id"); q.add_argument("--replay", action="store_true"); q.add_argument("--json", action="store_true")
    q = s.add_parser("pivot"); q.add_argument("case_dir", type=Path); q.add_argument("entity_id"); q.add_argument("--depth", type=int, default=1); q.add_argument("--json", action="store_true")
    q = s.add_parser("serve"); q.add_argument("case_dir", type=Path); q.add_argument("--port", type=int, default=8765); q.add_argument("--json", action="store_true")
    desktop = s.add_parser("desktop", help="Launch the authenticated local desktop workbench."); desktop.add_argument("--case-dir", type=Path); desktop.add_argument("--port", type=int, default=0)
    reset = s.add_parser("reset-login", help="Reset only the per-user local sign-in record."); reset.add_argument("--confirm", action="store_true", help="Confirm that the workbench is stopped and only its local account will be reset.")
    ask = s.add_parser("ask", help="Run an optional evidence-grounded assistant query."); ask.add_argument("case_dir", type=Path); ask.add_argument("--question", required=True); ask.add_argument("--task", choices=sorted(ALLOWED_TASKS), default="summarize_thread"); ask.add_argument("--provider", default="disabled", help="Explicit provider name; disabled is the safe default."); ask.add_argument("--offline", action="store_true", help="Use the deterministic local fake provider."); ask.add_argument("--thread-id", "--thread", dest="thread_id"); ask.add_argument("--hypothesis-id", "--hypothesis", dest="hypothesis_id"); ask.add_argument("--compare-hypothesis-id", dest="compare_hypothesis_id"); ask.add_argument("--entity-id", "--entity", dest="entity_id"); ask.add_argument("--relationship-id", "--relationship", dest="relationship_id"); ask.add_argument("--replay", action="store_true"); ask.add_argument("--report-section", choices=("events", "threads", "entities", "relationships", "evidence_gaps", "contradictions", "investigation", "graph")); ask.add_argument("--redact", action="append", default=[]); ask.add_argument("--redaction-config", type=Path); ask.add_argument("--max-context-items", type=int, default=200); ask.add_argument("--max-context-bytes", type=int, default=100000); ask.add_argument("--json", action="store_true", help="Emit compact JSON.")
    e = s.add_parser("export", help="Export a deterministic offline investigation report."); e.add_argument("case_dir", type=Path); e.add_argument("--format", choices=("json", "html", "markdown", "md"), default="json"); e.add_argument("--output", type=Path); e.add_argument("--view", choices=("case", "investigation"), default="case"); e.add_argument("--thread-id", "--thread", dest="thread_id"); e.add_argument("--hypothesis-id", "--hypothesis", dest="hypothesis_id"); e.add_argument("--redact", action="append", default=[], help="Sensitive category to redact; repeat or use comma-separated values."); e.add_argument("--redaction-config", type=Path); e.add_argument("--graph-start-type", choices=("entity", "event", "thread")); e.add_argument("--graph-start-id"); e.add_argument("--graph-depth", type=int, default=1); e.add_argument("--graph-limit", type=int, default=1000); e.add_argument("--json", action="store_true")
    hypothesis = s.add_parser("hypothesis"); hs = hypothesis.add_subparsers(dest="hypothesis_command", required=True)
    create = hs.add_parser("create"); create.add_argument("case_dir", type=Path); create.add_argument("--statement", required=True); create.add_argument("--status", default="open"); create.add_argument("--supporting", nargs="*", default=[]); create.add_argument("--weakening", nargs="*", default=[]); create.add_argument("--unresolved-gaps", nargs="*", default=[]); create.add_argument("--analyst", default="local"); create.add_argument("--json", action="store_true")
    update = hs.add_parser("update"); update.add_argument("case_dir", type=Path); update.add_argument("hypothesis_id"); update.add_argument("--status"); update.add_argument("--supporting", nargs="*", default=None); update.add_argument("--weakening", nargs="*", default=None); update.add_argument("--unresolved-gaps", nargs="*", default=None); update.add_argument("--analyst-note"); update.add_argument("--json", action="store_true")
    listing = hs.add_parser("list"); listing.add_argument("case_dir", type=Path); listing.add_argument("--json", action="store_true")
    note = s.add_parser("note"); ns = note.add_subparsers(dest="note_command", required=True)
    note_create = ns.add_parser("create"); note_create.add_argument("case_dir", type=Path); note_create.add_argument("--text", required=True); note_create.add_argument("--target-type"); note_create.add_argument("--target-id"); note_create.add_argument("--analyst", default="local"); note_create.add_argument("--json", action="store_true")
    note_list = ns.add_parser("list"); note_list.add_argument("case_dir", type=Path); note_list.add_argument("--json", action="store_true")
    decision = s.add_parser("decision"); ds = decision.add_subparsers(dest="decision_command", required=True)
    decision_create = ds.add_parser("create"); decision_create.add_argument("case_dir", type=Path); decision_create.add_argument("--statement", required=True); decision_create.add_argument("--status", default="open"); decision_create.add_argument("--evidence", nargs="*", default=[]); decision_create.add_argument("--rationale", default=""); decision_create.add_argument("--analyst", default="local"); decision_create.add_argument("--json", action="store_true")
    decision_list = ds.add_parser("list"); decision_list.add_argument("case_dir", type=Path); decision_list.add_argument("--json", action="store_true")
    return p
def main(argv=None):
    a = build_parser().parse_args(argv)
    try:
        if a.command == "analyze":
            r = analyze_case(a.case_dir, a.input, None if a.format == "auto" else a.format); _dump({"case_id": r["manifest"]["case_id"], "events": len(r["events"]), "entities": len(r["entities"]), "relationships": len(r["relationships"]), "threads": len(r["threads"]), "gaps": len(r["gaps"]), "contradictions": len(r["contradictions"]), "warnings": len(r["warnings"]), "output": str(a.case_dir.resolve())}, a.json); return 0
        if a.command == "hypothesis":
            if a.hypothesis_command == "create": _dump(create_hypothesis(a.case_dir, a.statement, a.supporting, a.weakening, a.unresolved_gaps, a.status, a.analyst), a.json)
            elif a.hypothesis_command == "update": _dump(update_hypothesis(a.case_dir, a.hypothesis_id, a.status, a.supporting, a.weakening, a.unresolved_gaps, a.analyst_note), a.json)
            else: _dump(list_investigation(a.case_dir, "hypotheses"), a.json)
            return 0
        if a.command == "note":
            _dump(create_note(a.case_dir, a.text, a.target_type, a.target_id, a.analyst), a.json) if a.note_command == "create" else _dump(list_investigation(a.case_dir, "notes"), a.json)
            return 0
        if a.command == "decision":
            _dump(create_decision(a.case_dir, a.statement, a.status, a.evidence, a.rationale, a.analyst), a.json) if a.decision_command == "create" else _dump(list_investigation(a.case_dir, "decisions"), a.json)
            return 0
        if a.command == "serve":
            from .workbench import serve_workbench
            return serve_workbench(a.case_dir, port=a.port)
        if a.command == "desktop":
            from .workbench import serve_workbench
            case_dir = a.case_dir or (Path(__file__).resolve().parents[1] / "examples" / "sample-case")
            return serve_workbench(case_dir, port=a.port, startup_protocol=True, control_stdin=True)
        if a.command == "reset-login":
            if not a.confirm:
                raise ValueError("Stop ForensicKit, then repeat reset-login with --confirm. No data was changed.")
            from .auth import AuthManager
            AuthManager().reset_account()
            print("Local sign-in reset. Case files and source evidence were not changed.")
            return 0
        if a.command == "ask":
            selections = [("thread", a.thread_id), ("hypothesis", a.hypothesis_id), ("entity", a.entity_id), ("relationship", a.relationship_id)]
            selected = [(kind, value) for kind, value in selections if value]
            if len(selected) > 1:
                raise AssistantError("ASSISTANT_SELECTION_INVALID", "Select only one thread, hypothesis, entity, or relationship.")
            selection_type, selection_id = (selected[0] if selected else ("report" if a.report_section else "case", None))
            if a.replay and selection_type != "thread":
                raise AssistantError("ASSISTANT_SELECTION_INVALID", "--replay requires --thread-id.")
            if a.replay:
                selection_type = "replay"
            if a.task == "compare_hypotheses" and not a.hypothesis_id:
                raise AssistantError("ASSISTANT_SELECTION_REQUIRED", "compare_hypotheses requires --hypothesis-id and optionally --compare-hypothesis-id.")
            result = ask_assistant(a.case_dir, a.question, task=a.task, selection_type=selection_type, selection_id=selection_id, compare_hypothesis_id=a.compare_hypothesis_id, provider_name=a.provider, offline=a.offline, redactions=a.redact, redaction_config=a.redaction_config, max_items=a.max_context_items, max_bytes=a.max_context_bytes, replay_selection=a.replay, report_section=a.report_section)
            _dump(result, a.json)
            return 0
        if a.command == "export":
            if a.thread_id and a.hypothesis_id:
                raise ValueError("select either --thread-id or --hypothesis-id, not both")
            if a.view == "investigation" and (a.thread_id or a.hypothesis_id):
                raise ValueError("--view investigation cannot be combined with a thread or hypothesis selection")
            scope = "investigation" if a.view == "investigation" else "thread" if a.thread_id else "hypothesis" if a.hypothesis_id else "case"
            scope_id = a.thread_id or a.hypothesis_id
            report = build_report(a.case_dir, scope=scope, scope_id=scope_id, redactions=a.redact, redaction_config=a.redaction_config, graph_start_type=a.graph_start_type, graph_start_id=a.graph_start_id, graph_depth=a.graph_depth, graph_limit=a.graph_limit)
            if a.output is None and a.format != "json":
                raise ValueError("--output is required for HTML and Markdown reports")
            content = export_report(report, a.output, a.format)
            if a.output is None:
                print(content, end="")
            else:
                _dump({"report_schema_version": report["report_schema_version"], "format": a.format, "output": str(a.output.resolve()), "case_id": report["case"]["case_id"], "analysis_id": report["case"]["analysis_id"]}, a.json)
            return 0
        d = load_case(a.case_dir)
        if a.command == "summary": _dump({"case_id": d["manifest"].get("case_id"), **{k: len(d[k]) for k in ("events", "entities", "relationships", "threads", "gaps", "contradictions", "warnings", "hypotheses", "notes", "decisions")}}, a.json)
        elif a.command == "threads": _dump(d["threads"], a.json)
        elif a.command == "thread": _dump(replay(a.case_dir, a.thread_id) if a.replay else next(t for t in d["threads"] if t["thread_id"] == a.thread_id), a.json)
        elif a.command == "pivot": _dump(pivot(a.case_dir, a.entity_id, a.depth), a.json)
        return 0
    except AssistantError as exc:
        print(json.dumps({"code": exc.code, "message": str(exc)}, sort_keys=True), file=sys.stderr); return 1
    except (OSError, ValueError, StopIteration, json.JSONDecodeError) as exc:
        print(json.dumps({"code": "CASE_ERROR", "message": str(exc)}, sort_keys=True), file=sys.stderr); return 1
