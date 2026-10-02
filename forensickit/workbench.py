"""Local-only HTTP presentation layer for the ForensicKit workbench."""

from __future__ import annotations

import json
import hmac
import sys
import threading
from copy import deepcopy
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .analysis import load_case, pivot, replay
from .assistant import ALLOWED_TASKS, AssistantError, ask_assistant
from .auth import AuthError, AuthManager
from .constants import SCHEMA_VERSION
from .graph import GRAPH_DEFAULT_LIMIT, GraphError, build_graph
from .investigation import (
    create_decision,
    create_hypothesis,
    create_note,
    update_decision,
    update_hypothesis,
)
from .timeutil import timestamp_sort_key


UI_ROOT = Path(__file__).with_name("ui")
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESULT_LIMIT = 5000
DEFAULT_EVENT_LIMIT = 2000
DEFAULT_PIVOT_LIMIT = 1000
DEFAULT_REPLAY_LIMIT = 1000
REPORT_EXPORT_MAX_BYTES = 8 * 1024 * 1024
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/logo-mark.svg": ("logo-mark.svg", "image/svg+xml"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}


def _contract(server: "WorkbenchServer", data, warnings=None) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": server.case_id,
        "data": data,
        "warnings": warnings or [],
    }


def _sort_events(events: list[dict]) -> list[dict]:
    return sorted(events, key=lambda event: (timestamp_sort_key(event.get("observed_at", {})), event.get("event_id", "")))


def _event_confidence(events: list[dict], relationships: list[dict]) -> dict[str, str]:
    rank = {"unknown": 0, "weak": 1, "moderate": 2, "high": 3}
    result = {event.get("event_id", ""): "unknown" for event in events}
    for relationship in relationships:
        strength = relationship.get("strength", "unknown")
        for event_id in relationship.get("evidence_ids", []):
            if rank.get(strength, 0) > rank.get(result.get(event_id, "unknown"), 0):
                result[event_id] = strength
    return result


def _time_range(events: list[dict]) -> dict:
    ordered = _sort_events(events)
    if not ordered:
        return {"start_utc": None, "end_utc": None, "start_original": None, "end_original": None, "uncertain": False}
    first, last = ordered[0], ordered[-1]
    return {
        "start_utc": first.get("observed_at", {}).get("utc"),
        "end_utc": last.get("observed_at", {}).get("utc"),
        "start_original": first.get("observed_at", {}).get("original"),
        "end_original": last.get("observed_at", {}).get("original"),
        "uncertain": any(event.get("observed_at", {}).get("quality") != "exact" for event in ordered),
    }


def _thread_view(thread: dict, events_by_id: dict[str, dict]) -> dict:
    result = deepcopy(thread)
    events = [events_by_id[event_id] for event_id in thread.get("event_ids", []) if event_id in events_by_id]
    result["time_range"] = _time_range(events)
    result["related_entities"] = sorted(thread.get("entity_ids", []))
    return result


def _query_limit(query: dict[str, list[str]], name: str, default: int) -> int:
    try:
        value = int(query.get(name, [str(default)])[0])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return min(value, MAX_RESULT_LIMIT)


def _query_offset(query: dict[str, list[str]]) -> int:
    try:
        value = int(query.get("offset", ["0"])[0])
    except (TypeError, ValueError) as exc:
        raise ValueError("offset must be a non-negative integer") from exc
    if value < 0:
        raise ValueError("offset must be a non-negative integer")
    return value


def _result_warning(kind: str, total: int, returned: int, limit: int) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "severity": "warning",
        "code": "WORKBENCH_RESULT_BOUNDED",
        "message": f"The {kind} response is bounded to {limit} records; {total - returned} records are omitted from this response.",
        "source_locator": kind,
    }


def _bounded_replay(replay_data: dict, limit: int) -> dict:
    result = deepcopy(replay_data)
    all_events = list(replay_data.get("events", []))
    selected_events = all_events[:limit]
    selected_ids = {event.get("event_id") for event in selected_events}
    all_relationships = list(replay_data.get("relationships", []))
    all_gaps = list(replay_data.get("gaps", []))
    all_contradictions = list(replay_data.get("contradictions", []))
    selected_relationships = [relationship for relationship in all_relationships if set(relationship.get("evidence_ids", [])) & selected_ids][:limit]
    selected_gaps = [gap for gap in all_gaps if set(gap.get("evidence_ids", [])) & selected_ids or set(gap.get("affected_event_ids", [])) & selected_ids][:limit]
    selected_contradictions = [contradiction for contradiction in all_contradictions if set(contradiction.get("evidence_ids", [])) & selected_ids][:limit]
    result["events"] = selected_events
    result["relationships"] = selected_relationships
    result["relationship_ids"] = [relationship.get("relationship_id") for relationship in selected_relationships]
    result["gaps"] = selected_gaps
    result["gap_ids"] = [gap.get("gap_id") for gap in selected_gaps]
    result["contradictions"] = selected_contradictions
    result["contradiction_ids"] = [contradiction.get("contradiction_id") for contradiction in selected_contradictions]
    result["result_bounds"] = {
        "events": {"total": len(all_events), "returned": len(selected_events), "limit": limit, "truncated": len(selected_events) < len(all_events)},
        "relationships": {"total": len(all_relationships), "returned": len(selected_relationships), "limit": limit, "truncated": len(selected_relationships) < len(all_relationships)},
        "gaps": {"total": len(all_gaps), "returned": len(selected_gaps), "limit": limit, "truncated": len(selected_gaps) < len(all_gaps)},
        "contradictions": {"total": len(all_contradictions), "returned": len(selected_contradictions), "limit": limit, "truncated": len(selected_contradictions) < len(all_contradictions)},
    }
    return result


def _bounded_pivot(result: dict, limit: int) -> dict:
    bounded = deepcopy(result)
    keys = ("entities", "events", "relationships", "threads", "hypotheses", "gaps", "contradictions")
    bounds = {}
    for key in keys:
        values = list(result.get(key, []))
        bounded[key] = values[:limit]
        bounds[key] = {"total": len(values), "returned": len(bounded[key]), "limit": limit, "truncated": len(bounded[key]) < len(values)}
    id_keys = {"events": "event_ids", "relationships": "relationship_ids", "threads": "thread_ids", "hypotheses": "hypothesis_ids", "gaps": "gap_ids", "contradictions": "contradiction_ids"}
    for value_key, id_key in id_keys.items():
        values = list(result.get(id_key, []))
        bounded[id_key] = values[:limit]
        if len(values) > limit:
            bounded[f"omitted_{id_key}"] = values[limit:]
    bounded["result_bounds"] = bounds
    return bounded


def _analysis_config(case_dir: Path) -> tuple[dict, list[dict]]:
    path = case_dir / "analysis-config.json"
    if not path.exists():
        return {}, [{"severity": "warning", "code": "WORKBENCH_CONFIG_MISSING", "message": "Analysis configuration is missing."}]
    try:
        return json.loads(path.read_text(encoding="utf-8")), []
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}, [{"severity": "warning", "code": "WORKBENCH_CONFIG_INVALID", "message": "Analysis configuration could not be read safely."}]


def _overview(server: "WorkbenchServer", data: dict) -> dict:
    config, config_warnings = _analysis_config(server.case_dir)
    manifest = data.get("manifest", {})
    safe_inputs = []
    for item in manifest.get("inputs", []):
        safe_inputs.append({key: item.get(key) for key in ("file_id", "relative_path", "sha256", "size_bytes", "detected_format", "parser", "parser_version")})
    return {
        "manifest": {
            "schema_version": manifest.get("schema_version"),
            "case_id": manifest.get("case_id"),
            "created_at_utc": manifest.get("created_at_utc"),
            "import_batch_id": manifest.get("import_batch_id"),
            "analysis_config_hash": manifest.get("analysis_config_hash"),
            "inputs": safe_inputs,
            "archive": manifest.get("archive"),
        },
        "counts": {key: len(data.get(key, [])) for key in ("events", "entities", "relationships", "threads", "gaps", "contradictions", "warnings", "hypotheses", "notes", "decisions")},
        "warnings": data.get("warnings", []) + config_warnings,
        "analysis_config": config,
        "versions": {
            "schema_version": SCHEMA_VERSION,
            "parser_versions": config.get("parser_versions", {}),
            "rule_versions": config.get("rule_versions", {}),
        },
    }


class WorkbenchServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, case_dir: Path, auth_manager: AuthManager | None = None, on_setup_complete=None):
        self.case_dir = Path(case_dir).resolve()
        if not self.case_dir.is_dir():
            raise ValueError("case directory is not available")
        if not address or address[0] not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("workbench must bind to localhost")
        self.auth = auth_manager or AuthManager()
        self.on_setup_complete = on_setup_complete
        initial = load_case(self.case_dir)
        self.case_id = initial.get("manifest", {}).get("case_id")
        if not self.case_id:
            raise ValueError("case manifest is unavailable")
        super().__init__(address, WorkbenchRequestHandler)


class WorkbenchRequestHandler(BaseHTTPRequestHandler):
    server: WorkbenchServer
    server_version = "ForensicKit"
    sys_version = ""

    def version_string(self):
        return "ForensicKit"

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler otherwise emits an HTML error page and a
        # Python version header for unsupported methods and malformed requests.
        unsupported_method = code == 501
        self._error(
            "METHOD_NOT_ALLOWED" if unsupported_method else "REQUEST_INVALID",
            "This request method is not available." if unsupported_method else "The request could not be processed.",
            405 if unsupported_method else code,
        )

    def log_message(self, format, *args):
        return

    def _headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")

    def _json(self, payload, status=200, extra_headers=()):
        body = json.dumps(payload, ensure_ascii=True, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self._headers("application/json; charset=utf-8")
        for name, value in extra_headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code: str, message: str, status: int):
        self._json({"schema_version": SCHEMA_VERSION, "error": {"code": code, "message": message}}, status)

    def _static(self, path: str):
        item = STATIC_FILES.get(path)
        if item is None:
            self._error("NOT_FOUND", "Workbench resource not found.", 404)
            return
        filename, content_type = item
        try:
            body = (UI_ROOT / filename).read_bytes()
        except (OSError, IOError):
            self._error("UI_UNAVAILABLE", "Workbench interface is unavailable.", 500)
            return
        self.send_response(200)
        self._headers(content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _case_parts(self, path: str):
        parts = [unquote(part) for part in path.split("/") if part]
        if len(parts) < 4 or parts[0] != "api" or parts[1] != "cases":
            self._error("NOT_FOUND", "Workbench API resource not found.", 404)
            return None
        if parts[2] != self.server.case_id:
            self._error("CASE_NOT_FOUND", "The requested case is not loaded.", 404)
            return None
        return parts[3:]

    def _data(self):
        return load_case(self.server.case_dir)

    def _is_trusted_local(self) -> bool:
        try:
            remote = self.client_address[0]
            import ipaddress
            if not ipaddress.ip_address(remote).is_loopback:
                return False
        except (ValueError, IndexError):
            return False
        port = self.server.server_port
        return self.headers.get("Host", "").lower() in {
            f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"
        }

    def _require_same_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if self.headers.get("Sec-Fetch-Site", "").casefold() in {"cross-site", "same-site"}:
            self._error("REQUEST_ORIGIN_INVALID", "Cross-origin requests are not allowed.", 403)
            return False
        if origin:
            expected = f"http://{self.headers.get('Host', '').lower()}"
            if origin.rstrip("/").lower() != expected:
                self._error("REQUEST_ORIGIN_INVALID", "Cross-origin requests are not allowed.", 403)
                return False
        return True

    def _session_cookie(self) -> str | None:
        try:
            cookies = SimpleCookie()
            cookies.load(self.headers.get("Cookie", ""))
            value = cookies.get("FKSESSION")
            return value.value if value else None
        except (ValueError, TypeError):
            return None

    def _authenticated_session(self, *, csrf: bool = False):
        resolved = self.server.auth.resolve_session(self._session_cookie())
        if resolved is None:
            self._error("AUTHENTICATION_REQUIRED", "Sign in to access the local case.", 401)
            return None
        session_id, session = resolved
        if csrf and not hmac.compare_digest(session.csrf_token, self.headers.get("X-FK-CSRF", "")):
            self._error("CSRF_TOKEN_INVALID", "The request token is missing or invalid.", 403)
            return None
        return session_id, session

    def _session_headers(self, session_id: str) -> tuple[tuple[str, str], ...]:
        return (("Set-Cookie", f"FKSESSION={session_id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=1800"),)

    def _auth_state(self):
        resolved = self.server.auth.resolve_session(self._session_cookie())
        if resolved is None:
            return {
                "setup_required": self.server.auth.setup_required,
                "authenticated": False,
                "username": None,
                "csrf_token": None,
            }
        _, session = resolved
        return {
            "setup_required": False,
            "authenticated": True,
            "username": session.username,
            "csrf_token": session.csrf_token,
        }

    def _get(self, path: str, query: dict[str, list[str]]):
        if not self._is_trusted_local():
            return self._error("LOCAL_REQUEST_REQUIRED", "The workbench accepts only loopback requests.", 403)
        if path == "/api/auth/state":
            return self._json(_contract(self.server, self._auth_state()))
        if path == "/api/settings":
            if self._authenticated_session() is None:
                return
            return self._json(_contract(self.server, self.server.auth.get_settings()))
        if path == "/api/bootstrap":
            if self._authenticated_session() is None:
                return
            data = self._data()
            return self._json(_contract(self.server, _overview(self.server, data)))
        if path.startswith("/api/") and self._authenticated_session() is None:
            return
        parts = self._case_parts(path)
        if parts is None:
            return
        data = self._data()
        if parts == ["summary"]:
            return self._json(_contract(self.server, _overview(self.server, data)))
        if parts == ["graph"]:
            graph_data = build_graph(
                data,
                query.get("start_type", [""])[0],
                query.get("start_id", [""])[0],
                depth=query.get("depth", ["1"])[0],
                limit=query.get("limit", [str(GRAPH_DEFAULT_LIMIT)])[0],
                relationship_types=query.get("relationship_type", []),
                confidence=query.get("confidence", [""])[0],
                entity_type=query.get("entity_type", [""])[0],
                thread_id=query.get("thread_id", [""])[0],
            )
            warnings = list(data.get("warnings", []))
            if any(bound.get("truncated") for bound in graph_data.get("result_bounds", {}).values()):
                largest = max(graph_data["result_bounds"].values(), key=lambda bound: bound["total"] - bound["returned"])
                warnings.append({
                    "schema_version": SCHEMA_VERSION,
                    "severity": "warning",
                    "code": "GRAPH_RESULT_BOUNDED",
                    "message": f"The graph response is bounded to {largest['limit']} records per kind; {largest['total'] - largest['returned']} records are omitted from this response.",
                    "source_locator": "graph",
                })
            return self._json(_contract(self.server, graph_data, warnings))
        if parts == ["events"]:
            all_events = _sort_events(data.get("events", []))
            limit = _query_limit(query, "limit", DEFAULT_EVENT_LIMIT)
            offset = _query_offset(query)
            events = all_events[offset:offset + limit]
            warnings = list(data.get("warnings", []))
            if len(events) < len(all_events):
                warnings.append(_result_warning("timeline", len(all_events), len(events), limit))
            return self._json(_contract(self.server, {"events": events, "event_confidence": _event_confidence(events, data.get("relationships", [])), "total": len(all_events), "offset": offset, "limit": limit, "truncated": len(events) < len(all_events)}, warnings))
        if parts == ["threads"]:
            by_id = {event.get("event_id"): event for event in data.get("events", [])}
            threads = [_thread_view(thread, by_id) for thread in data.get("threads", [])]
            return self._json(_contract(self.server, threads, data.get("warnings", [])))
        if parts == ["investigation"]:
            return self._json(_contract(self.server, {key: data.get(key, []) for key in ("hypotheses", "notes", "decisions")}))
        if parts == ["gaps"]:
            return self._json(_contract(self.server, data.get("gaps", [])))
        if parts == ["contradictions"]:
            return self._json(_contract(self.server, data.get("contradictions", [])))
        if parts == ["entities"]:
            return self._json(_contract(self.server, sorted(data.get("entities", []), key=lambda entity: entity.get("entity_id", ""))))
        if len(parts) == 2 and parts[0] == "evidence":
            event = next((event for event in data.get("events", []) if event.get("event_id") == parts[1]), None)
            if event is None:
                return self._error("EVIDENCE_NOT_FOUND", "Evidence event not found.", 404)
            event_id = event["event_id"]
            related = {
                "event": event,
                "relationships": [relationship for relationship in data.get("relationships", []) if event_id in relationship.get("evidence_ids", [])],
                "gaps": [gap for gap in data.get("gaps", []) if event_id in gap.get("evidence_ids", []) or event_id in gap.get("affected_event_ids", [])],
                "contradictions": [contradiction for contradiction in data.get("contradictions", []) if event_id in contradiction.get("evidence_ids", [])],
            }
            return self._json(_contract(self.server, related))
        if len(parts) >= 2 and parts[0] == "threads":
            thread_id = parts[1]
            thread = next((thread for thread in data.get("threads", []) if thread.get("thread_id") == thread_id), None)
            if thread is None:
                return self._error("THREAD_NOT_FOUND", "Candidate thread not found.", 404)
            by_id = {event.get("event_id"): event for event in data.get("events", [])}
            if query.get("replay", [""])[0].casefold() in {"1", "true", "yes"}:
                limit = _query_limit(query, "limit", DEFAULT_REPLAY_LIMIT)
                replay_data = _bounded_replay(replay(self.server.case_dir, thread_id), limit)
                warnings = []
                if any(bound["truncated"] for bound in replay_data["result_bounds"].values()):
                    largest = max(replay_data["result_bounds"].values(), key=lambda bound: bound["total"] - bound["returned"])
                    warnings.append(_result_warning("replay", largest["total"], largest["returned"], limit))
                return self._json(_contract(self.server, {"thread": _thread_view(thread, by_id), "replay": replay_data}, warnings))
            return self._json(_contract(self.server, _thread_view(thread, by_id)))
        if len(parts) == 3 and parts[0] == "entities" and parts[2] == "pivot":
            try:
                depth = int(query.get("depth", ["1"])[0])
            except ValueError:
                return self._error("INVALID_PIVOT_DEPTH", "Pivot depth must be an integer from 0 to 3.", 400)
            limit = _query_limit(query, "limit", DEFAULT_PIVOT_LIMIT)
            bounded = _bounded_pivot(pivot(self.server.case_dir, parts[1], depth), limit)
            warnings = []
            if any(bound["truncated"] for bound in bounded["result_bounds"].values()):
                total = max(bound["total"] for bound in bounded["result_bounds"].values())
                returned = max(bound["returned"] for bound in bounded["result_bounds"].values())
                warnings.append(_result_warning("pivot", total, returned, limit))
            return self._json(_contract(self.server, bounded, warnings))
        return self._error("NOT_FOUND", "Workbench API resource not found.", 404)

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("request body length is invalid") from exc
        if length <= 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("request body is empty or too large")
        raw = self.rfile.read(length)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    @staticmethod
    def _text(payload: dict, name: str, required=False, limit=20000):
        value = payload.get(name)
        if value is None and not required:
            return None
        if not isinstance(value, str):
            raise ValueError(f"{name} must be text")
        value = value.strip() if name not in {"analyst_note", "rationale", "password"} else value
        if required and not value:
            raise ValueError(f"{name} cannot be empty")
        if len(value) > limit:
            raise ValueError(f"{name} is too long")
        return value

    @staticmethod
    def _refs(payload: dict, name: str) -> list[str] | None:
        value = payload.get(name)
        if value is None:
            return None
        if not isinstance(value, list) or len(value) > 500 or not all(isinstance(item, str) for item in value):
            raise ValueError(f"{name} must be a list of text references")
        return value

    def _post(self, path: str):
        parts = self._case_parts(path)
        if parts is None:
            return
        payload = self._body()
        case_dir = self.server.case_dir
        if parts == ["assistant"]:
            question = self._text(payload, "question", True, 4000)
            task = self._text(payload, "task") or "summarize_thread"
            if task not in ALLOWED_TASKS:
                raise AssistantError("ASSISTANT_TASK_INVALID", "Unsupported assistant task.")
            provider = self._text(payload, "provider") or "disabled"
            if provider not in {"disabled", "fake"}:
                raise AssistantError("PROVIDER_UNAVAILABLE", "The workbench permits only the disabled or deterministic fake provider.")
            offline = payload.get("offline", False)
            if not isinstance(offline, bool):
                raise AssistantError("ASSISTANT_REQUEST_INVALID", "offline must be a boolean.")
            selection_type = self._text(payload, "selection_type") or "case"
            selection_id = self._text(payload, "selection_id")
            if selection_type not in {"case", "thread", "hypothesis", "entity", "replay", "report", "relationship"}:
                raise AssistantError("ASSISTANT_SELECTION_INVALID", "Unsupported assistant selection type.")
            if selection_type in {"thread", "hypothesis", "entity", "replay", "relationship"} and not selection_id:
                raise AssistantError("ASSISTANT_SELECTION_REQUIRED", "The selected assistant object requires an ID.")
            report_section = self._text(payload, "report_section")
            if report_section and report_section not in {"events", "threads", "entities", "relationships", "evidence_gaps", "contradictions", "investigation", "graph"}:
                raise AssistantError("ASSISTANT_REPORT_SECTION_INVALID", "Unsupported report section.")
            result = ask_assistant(case_dir, question, task=task, selection_type=selection_type, selection_id=selection_id, compare_hypothesis_id=self._text(payload, "compare_hypothesis_id"), provider_name=provider, offline=offline, redactions=self._refs(payload, "redactions") or [], max_items=min(int(payload.get("max_context_items", 200)), 1000), max_bytes=min(int(payload.get("max_context_bytes", 100000)), 200000), replay_selection=selection_type == "replay", report_section=report_section)
            return self._json(_contract(self.server, result))
        if parts == ["reports", "export"]:
            from .report import REPORT_SCHEMA_VERSION, build_report, export_report

            format_name = (self._text(payload, "format", True, 16) or "").casefold()
            extensions = {"json": "json", "html": "html", "markdown": "md", "md": "md"}
            if format_name not in extensions:
                raise ValueError("report format must be json, html, or markdown")
            scope = self._text(payload, "scope") or "case"
            if scope not in {"case", "investigation", "thread", "hypothesis"}:
                raise ValueError("report scope must be case, investigation, thread, or hypothesis")
            scope_id = self._text(payload, "scope_id", limit=256)
            if scope in {"thread", "hypothesis"} and not scope_id:
                raise ValueError("a thread or hypothesis must be selected for this report scope")
            if scope not in {"thread", "hypothesis"} and scope_id:
                raise ValueError("this report scope does not accept an object ID")
            redactions = self._refs(payload, "redactions") or []
            if len(redactions) > 10:
                raise ValueError("at most 10 redaction categories may be selected")
            report = build_report(case_dir, scope=scope, scope_id=scope_id, redactions=redactions)
            content = export_report(report, None, format_name)
            encoded = content.encode("utf-8")
            if len(encoded) > REPORT_EXPORT_MAX_BYTES:
                return self._error("REPORT_RESULT_TOO_LARGE", "The complete report exceeds the workbench download limit. Use the documented CLI export for this case.", 413)
            case_token = "".join(ch if ch.isascii() and (ch.isalnum() or ch in "-_") else "_" for ch in str(self.server.case_id))[:64] or "case"
            filename = f"forensickit-{case_token}-{scope}.{extensions[format_name]}"
            content_types = {"json": "application/json; charset=utf-8", "html": "text/html; charset=utf-8", "markdown": "text/markdown; charset=utf-8", "md": "text/markdown; charset=utf-8"}
            return self._json(_contract(self.server, {
                "format": "markdown" if format_name == "md" else format_name,
                "filename": filename,
                "content_type": content_types[format_name],
                "content": content,
                "byte_size": len(encoded),
                "report_schema_version": REPORT_SCHEMA_VERSION,
                "scope": report.get("scope"),
            }))
        if parts == ["hypotheses"]:
            result = create_hypothesis(case_dir, self._text(payload, "statement", True), self._refs(payload, "supporting_evidence_ids") or [], self._refs(payload, "weakening_evidence_ids") or [], self._refs(payload, "unresolved_gap_ids") or [], self._text(payload, "status") or "open", self._text(payload, "analyst") or "local")
            return self._json(_contract(self.server, result), 201)
        if len(parts) == 2 and parts[0] == "hypotheses":
            result = update_hypothesis(case_dir, parts[1], self._text(payload, "status"), self._refs(payload, "supporting_evidence_ids"), self._refs(payload, "weakening_evidence_ids"), self._refs(payload, "unresolved_gap_ids"), self._text(payload, "analyst_note"))
            return self._json(_contract(self.server, result))
        if parts == ["notes"]:
            result = create_note(case_dir, self._text(payload, "text", True), self._text(payload, "target_type"), self._text(payload, "target_id"), self._text(payload, "analyst") or "local")
            return self._json(_contract(self.server, result), 201)
        if parts == ["decisions"]:
            result = create_decision(case_dir, self._text(payload, "statement", True), self._text(payload, "status") or "open", self._refs(payload, "evidence_ids") or [], self._text(payload, "rationale") or "", self._text(payload, "analyst") or "local")
            return self._json(_contract(self.server, result), 201)
        if len(parts) == 2 and parts[0] == "decisions":
            result = update_decision(case_dir, parts[1], self._text(payload, "status"), self._text(payload, "rationale"))
            return self._json(_contract(self.server, result))
        return self._error("NOT_FOUND", "Workbench API resource not found.", 404)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in STATIC_FILES:
            return self._static(parsed.path)
        try:
            return self._get(parsed.path, parse_qs(parsed.query, keep_blank_values=True))
        except GraphError as exc:
            self._error(exc.code, str(exc), 400)
        except AuthError as exc:
            self._error(exc.code, str(exc), exc.status)
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, StopIteration):
            self._error("CASE_DATA_INVALID", "Case data is missing or malformed.", 500)
        except ValueError as exc:
            self._error("REQUEST_INVALID", str(exc), 400)
        except Exception:
            self._error("WORKBENCH_ERROR", "The local workbench could not complete the request.", 500)

    def do_POST(self):
        parsed = urlparse(self.path)
        try:
            if not self._is_trusted_local():
                return self._error("LOCAL_REQUEST_REQUIRED", "The workbench accepts only loopback requests.", 403)
            if not self._require_same_origin():
                return
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip().casefold() != "application/json":
                return self._error("REQUEST_CONTENT_TYPE_INVALID", "State-changing requests require application/json.", 415)
            if parsed.path in {"/api/auth/setup", "/api/auth/login"}:
                payload = self._body()
                if parsed.path.endswith("/setup"):
                    session_id, session = self.server.auth.create_account(
                        self._text(payload, "setup_code", True, 128),
                        self._text(payload, "username", True, 64),
                        self._text(payload, "password", True, 1024),
                    )
                    if self.server.on_setup_complete is not None:
                        self.server.on_setup_complete()
                    return self._json(_contract(self.server, {"username": session.username, "csrf_token": session.csrf_token}), 201, self._session_headers(session_id))
                session_id, session = self.server.auth.authenticate(
                    self._text(payload, "username", True, 64),
                    self._text(payload, "password", True, 1024),
                    self.client_address[0],
                )
                return self._json(_contract(self.server, {"username": session.username, "csrf_token": session.csrf_token}), 200, self._session_headers(session_id))
            if parsed.path == "/api/auth/logout":
                authenticated = self._authenticated_session(csrf=True)
                if authenticated is None:
                    return
                self.server.auth.revoke_session(authenticated[0])
                return self._json(_contract(self.server, {"logged_out": True}), 200, (("Set-Cookie", "FKSESSION=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"),))
            if parsed.path == "/api/settings":
                if self._authenticated_session(csrf=True) is None:
                    return
                payload = self._body()
                return self._json(_contract(self.server, self.server.auth.update_settings(self._text(payload, "theme", True, 16))))
            if self._authenticated_session(csrf=True) is None:
                return
            return self._post(parsed.path)
        except AuthError as exc:
            self._error(exc.code, str(exc), exc.status)
        except AssistantError as exc:
            self._error(exc.code, str(exc), 400)
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, StopIteration):
            self._error("CASE_DATA_INVALID", "Case data is missing or malformed.", 500)
        except ValueError as exc:
            self._error("REQUEST_INVALID", str(exc), 400)
        except Exception:
            self._error("WORKBENCH_ERROR", "The local workbench could not complete the request.", 500)


def serve_workbench(
    case_dir: Path,
    port: int = 8765,
    *,
    startup_protocol: bool = False,
    control_stdin: bool = False,
    auth_manager: AuthManager | None = None,
) -> int:
    """Serve the authenticated workbench on the loopback interface only."""
    if port < 0 or port > 65535:
        raise ValueError("port must be between 0 and 65535")
    manager = auth_manager or AuthManager()
    setup_callback = (lambda: print("ACCOUNT_SETUP_COMPLETE=1", flush=True)) if startup_protocol else None
    server = WorkbenchServer(("127.0.0.1", port), case_dir, auth_manager=manager, on_setup_complete=setup_callback)
    url = f"http://127.0.0.1:{server.server_port}/"
    if startup_protocol:
        if manager.bootstrap_code:
            print(f"BOOTSTRAP_CODE={manager.bootstrap_code}", flush=True)
        print(f"WORKBENCH_URL={url}", flush=True)
        print("WORKBENCH_READY=1", flush=True)
    else:
        if manager.bootstrap_code:
            print("First-run setup code (shown once; enter it in the local workbench):", flush=True)
            print(manager.bootstrap_code, flush=True)
        print(f"ForensicKit workbench listening at {url}", flush=True)
    if control_stdin:
        def wait_for_quit():
            try:
                command = sys.stdin.readline()
            except (OSError, ValueError):
                return
            if command.strip() == "QUIT":
                server.shutdown()

        threading.Thread(target=wait_for_quit, name="forensickit-launch-control", daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0
