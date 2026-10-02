import json
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from forensickit.analysis import analyze_case
from forensickit.auth import AuthManager
import forensickit.workbench as workbench_module
from forensickit.workbench import WorkbenchServer


ROOT = Path(__file__).resolve().parent.parent
_SESSIONS = {}


def _contrast_ratio(first: str, second: str) -> float:
    def luminance(color: str) -> float:
        channels = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4 for channel in channels]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    bright, dark = sorted((luminance(first), luminance(second)), reverse=True)
    return (bright + 0.05) / (dark + 0.05)


def test_workbench_theme_text_and_focus_contrast():
    css = (ROOT / "forensickit" / "ui" / "styles.css").read_text(encoding="utf-8")
    for selector in (":root", ':root[data-theme="dark"]', ":root:not([data-theme])"):
        match = re.search(re.escape(selector) + r"\s*\{([^{}]*)\}", css)
        assert match, f"missing theme token block: {selector}"
        values = dict(re.findall(r"(--[\w-]+)\s*:\s*(#[0-9a-fA-F]{6})", match.group(1)))
        for foreground, background, minimum in (
            ("--text", "--panel", 7.0),
            ("--muted", "--bg", 4.5),
            ("--muted", "--panel", 4.5),
            ("--muted-strong", "--panel", 4.5),
            ("--accent-strong", "--accent-soft", 4.5),
            ("--success-text", "--success-bg", 4.5),
            ("--warning-text", "--warn-bg", 4.5),
            ("--danger-text", "--danger-bg", 4.5),
            ("--focus-ring", "--panel", 3.0),
        ):
            assert foreground in values and background in values, f"missing {foreground}/{background} for {selector}"
            ratio = _contrast_ratio(values[foreground], values[background])
            assert ratio >= minimum, f"{selector}: {foreground} on {background} is {ratio:.2f}:1 (needs {minimum}:1)"


def test_mobile_workbench_controls_have_touch_targets():
    css = (ROOT / "forensickit" / "ui" / "styles.css").read_text(encoding="utf-8")
    start = css.find("@media (max-width: 520px)")
    end = css.find("@media ", start + 1)
    assert start >= 0 and end > start, "missing compact mobile layout rules"
    rules = css[start:end]
    assert ".auth-shell" in rules and ".auth-card" in rules, "mobile auth layout should use compact spacing"
    assert re.search(r"input,\s*textarea,\s*select,\s*\.button\s*\{\s*min-height:\s*44px", rules), "mobile controls should provide 44px touch targets"


def test_windows_startup_launcher_is_checkout_relative_and_has_runtime_fallback():
    launcher = (ROOT / "start-workbench.cmd").read_text(encoding="utf-8")
    assert 'set "FK_PROJECT_ROOT=%~dp0"' in launcher
    assert 'set "FK_CASE=%FK_PROJECT_ROOT%examples\\sample-case"' in launcher
    assert 'pushd "%FK_PROJECT_ROOT%"' in launcher
    assert "py -3 -m forensickit serve" in launcher
    assert '"%FK_PYTHON%" -m forensickit serve' in launcher
    assert "goto case_missing" in launcher and "goto launcher_missing" in launcher


def _request(base_url, path, method="GET", payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(base_url + path, data=body, method=method)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    session = _SESSIONS.get(base_url)
    if session and session.get("cookie"):
        request.add_header("Cookie", session["cookie"])
    if method == "POST" and session and session.get("csrf"):
        request.add_header("X-FK-CSRF", session["csrf"])
    with urllib.request.urlopen(request, timeout=5) as response:
        result = json.loads(response.read().decode("utf-8"))
        if session is not None:
            set_cookie = response.headers.get("Set-Cookie")
            if set_cookie:
                session["cookie"] = set_cookie.split(";", 1)[0]
            if result.get("data", {}).get("csrf_token"):
                session["csrf"] = result["data"]["csrf_token"]
        return response.status, result


def _start(case_dir, authenticate=True):
    auth = AuthManager(case_dir.parent / "workbench-test-user-state")
    server = WorkbenchServer(("127.0.0.1", 0), case_dir, auth_manager=auth)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    _SESSIONS[base_url] = {"cookie": None, "csrf": None}
    if authenticate:
        status, state = _request(base_url, "/api/auth/state")
        assert status == 200 and state["data"]["setup_required"]
        status, _ = _request(base_url, "/api/auth/setup", "POST", {
            "setup_code": auth.bootstrap_code,
            "username": "reviewer",
            "password": "ForensicKit test passphrase 2026!",
        })
        assert status == 201 and _SESSIONS[base_url]["csrf"]
    return server, thread, base_url


def _sample_case(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    source = ROOT / "examples" / "sample-case" / "evidence" / "events.jsonl"
    (evidence / "events.jsonl").write_bytes(source.read_bytes())
    case_dir = tmp_path / "case"
    result = analyze_case(case_dir, evidence)
    return case_dir, result


def test_workbench_sample_case_workflows(tmp_path: Path):
    case_dir, result = _sample_case(tmp_path)
    source_path = tmp_path / "evidence" / "events.jsonl"
    source_before = source_path.read_bytes()
    server, thread, base_url = _start(case_dir)
    try:
        status, bootstrap = _request(base_url, "/api/bootstrap")
        assert status == 200
        assert bootstrap["case_id"] == result["manifest"]["case_id"]
        assert bootstrap["data"]["counts"]["events"] == len(result["events"])
        assert bootstrap["data"]["warnings"]

        status, events = _request(base_url, f"/api/cases/{result['manifest']['case_id']}/events")
        assert status == 200 and events["data"]["events"]
        assert events["warnings"]
        status, bounded_events = _request(base_url, f"/api/cases/{result['manifest']['case_id']}/events?limit=1")
        assert status == 200
        assert bounded_events["data"]["truncated"] and bounded_events["data"]["total"] == len(result["events"])
        assert any(item["code"] == "WORKBENCH_RESULT_BOUNDED" for item in bounded_events["warnings"])

        thread_id = result["threads"][0]["thread_id"]
        status, thread_view = _request(base_url, f"/api/cases/{result['manifest']['case_id']}/threads/{thread_id}?replay=1")
        assert status == 200 and thread_view["data"]["replay"]["events"]
        assert thread_view["data"]["replay"]["gaps"]
        status, bounded_replay = _request(base_url, f"/api/cases/{result['manifest']['case_id']}/threads/{thread_id}?replay=1&limit=1")
        assert status == 200 and bounded_replay["data"]["replay"]["result_bounds"]["events"]["truncated"]

        entity_id = next(entity["entity_id"] for entity in result["entities"] if entity["type"] == "session")
        encoded_entity = urllib.parse.quote(entity_id, safe="")
        status, pivoted = _request(base_url, f"/api/cases/{result['manifest']['case_id']}/entities/{encoded_entity}/pivot?depth=1")
        assert status == 200 and pivoted["data"]["event_ids"]
        assert pivoted["data"]["depth"] == 1
        status, bounded_pivot = _request(base_url, f"/api/cases/{result['manifest']['case_id']}/entities/{encoded_entity}/pivot?depth=1&limit=1")
        assert status == 200
        assert any(bound["truncated"] for bound in bounded_pivot["data"]["result_bounds"].values())

        event_id = result["events"][0]["event_id"]
        status, provenance = _request(base_url, f"/api/cases/{result['manifest']['case_id']}/evidence/{event_id}")
        assert status == 200
        assert provenance["data"]["event"]["provenance"]["record_fingerprint"]

        status, hypothesis = _request(base_url, f"/api/cases/{result['manifest']['case_id']}/hypotheses", "POST", {"statement": "Review the observed session.", "supporting_evidence_ids": [event_id]})
        assert status == 201
        status, note = _request(base_url, f"/api/cases/{result['manifest']['case_id']}/notes", "POST", {"text": "Treat command text as untrusted evidence.", "target_type": "event", "target_id": event_id})
        assert status == 201
        status, decision = _request(base_url, f"/api/cases/{result['manifest']['case_id']}/decisions", "POST", {"statement": "Keep attribution unresolved.", "evidence_ids": [event_id]})
        assert status == 201
        status, updated_decision = _request(base_url, f"/api/cases/{result['manifest']['case_id']}/decisions/{decision['data']['decision_id']}", "POST", {"status": "in_review"})
        assert status == 200 and updated_decision["data"]["status"] == "in_review"
        status, investigation = _request(base_url, f"/api/cases/{result['manifest']['case_id']}/investigation")
        assert status == 200
        assert any(item["hypothesis_id"] == hypothesis["data"]["hypothesis_id"] for item in investigation["data"]["hypotheses"])
        assert any(item["note_id"] == note["data"]["note_id"] for item in investigation["data"]["notes"])
        assert any(item["decision_id"] == decision["data"]["decision_id"] and item["status"] == "in_review" for item in investigation["data"]["decisions"])
        status, disabled_assistant = _request(base_url, f"/api/cases/{result['manifest']['case_id']}/assistant", "POST", {"task": "summarize_report", "question": "Summarize safely.", "provider": "disabled", "offline": False})
        assert status == 200 and disabled_assistant["data"]["status"] == "disabled"
        status, fake_assistant = _request(base_url, f"/api/cases/{result['manifest']['case_id']}/assistant", "POST", {"task": "summarize_thread", "question": "Summarize the selected thread.", "provider": "fake", "offline": True, "selection_type": "thread", "selection_id": thread_id, "redactions": ["user", "path"]})
        assert status == 200 and fake_assistant["data"]["provider"] == "fake"
        assert fake_assistant["data"]["response"]["validation"]["valid"]
        invalid_assistant = urllib.request.Request(base_url + f"/api/cases/{result['manifest']['case_id']}/assistant", data=json.dumps({"task": "not-a-task", "question": "x"}).encode("utf-8"), method="POST")
        invalid_assistant.add_header("Content-Type", "application/json")
        invalid_assistant.add_header("Cookie", _SESSIONS[base_url]["cookie"])
        invalid_assistant.add_header("X-FK-CSRF", _SESSIONS[base_url]["csrf"])
        try:
            urllib.request.urlopen(invalid_assistant, timeout=5)
        except urllib.error.HTTPError as error:
            assert error.code == 400
            assert json.loads(error.read().decode("utf-8"))["error"]["code"] == "ASSISTANT_TASK_INVALID"
        else:
            raise AssertionError("invalid assistant task was accepted")
        assert source_path.read_bytes() == source_before
        oversized = urllib.request.Request(base_url + f"/api/cases/{result['manifest']['case_id']}/notes", data=json.dumps({"text": "x" * 70000}).encode("utf-8"), method="POST")
        oversized.add_header("Content-Type", "application/json")
        oversized.add_header("Cookie", _SESSIONS[base_url]["cookie"])
        oversized.add_header("X-FK-CSRF", _SESSIONS[base_url]["csrf"])
        try:
            urllib.request.urlopen(oversized, timeout=5)
        except urllib.error.HTTPError as error:
            assert error.code == 400
        except (ConnectionAbortedError, ConnectionResetError):
            # The handler rejects the body before reading it. Windows may
            # report an aborted/reset socket instead of surfacing the
            # structured 400 response when the client is still transmitting.
            pass
        else:
            raise AssertionError("oversized workbench request was accepted")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_workbench_report_export_formats_redaction_bounds_and_source_safety(tmp_path: Path):
    case_dir, result = _sample_case(tmp_path)
    source_path = tmp_path / "evidence" / "events.jsonl"
    source_before = source_path.read_bytes()
    server, thread, base_url = _start(case_dir)
    endpoint = f"/api/cases/{result['manifest']['case_id']}/reports/export"
    try:
        exports = {}
        for format_name in ("json", "html", "markdown"):
            status, response = _request(base_url, endpoint, "POST", {
                "format": format_name,
                "scope": "case",
                "redactions": ["path", "user", "command_line", "ip", "domain"],
            })
            assert status == 200
            data = response["data"]
            assert data["format"] == format_name and data["report_schema_version"] == "1.0"
            assert data["byte_size"] == len(data["content"].encode("utf-8"))
            assert ".." not in data["filename"] and "/" not in data["filename"] and "\\" not in data["filename"]
            exports[format_name] = data

        report = json.loads(exports["json"]["content"])
        assert report["case"]["case_id"] == result["manifest"]["case_id"]
        assert report["events"] and all(event.get("report_provenance") for event in report["events"])
        assert report["evidence_gaps"]
        assert "contradictions" in report and "EVTX PARTIALLY VALIDATED — pending approved Windows Security and PowerShell binary fixtures" == report["evtx_validation_status"]
        assert "[REDACTED:path]" in exports["json"]["content"]
        assert "source_payload" not in exports["json"]["content"]
        assert str(source_path) not in exports["json"]["content"]
        assert "Content-Security-Policy" in exports["html"]["content"]
        assert "<script" not in exports["html"]["content"].casefold()
        assert exports["markdown"]["content"].startswith("# ForensicKit Investigation Report")
        status, again = _request(base_url, endpoint, "POST", {"format": "json", "scope": "case", "redactions": ["path", "user", "command_line", "ip", "domain"]})
        assert status == 200 and again["data"]["content"] == exports["json"]["content"]

        thread_id = result["threads"][0]["thread_id"]
        status, thread_report = _request(base_url, endpoint, "POST", {"format": "json", "scope": "thread", "scope_id": thread_id})
        assert status == 200 and json.loads(thread_report["data"]["content"])["scope"] == {"type": "thread", "id": thread_id}
        event_id = result["events"][0]["event_id"]
        status, hypothesis = _request(base_url, f"/api/cases/{result['manifest']['case_id']}/hypotheses", "POST", {"statement": "Review the sample timeline.", "supporting_evidence_ids": [event_id]})
        assert status == 201
        status, hypothesis_report = _request(base_url, endpoint, "POST", {"format": "json", "scope": "hypothesis", "scope_id": hypothesis["data"]["hypothesis_id"]})
        assert status == 200 and json.loads(hypothesis_report["data"]["content"])["scope"]["id"] == hypothesis["data"]["hypothesis_id"]
        status, note = _request(base_url, f"/api/cases/{result['manifest']['case_id']}/notes", "POST", {"text": "Analyst-only report annotation."})
        assert status == 201
        status, investigation_report = _request(base_url, endpoint, "POST", {"format": "json", "scope": "investigation", "redactions": ["text"]})
        assert status == 200
        investigation = json.loads(investigation_report["data"]["content"])["investigation"]
        assert any(item["note_id"] == note["data"]["note_id"] and item["authorship"] == "analyst-authored" for item in investigation["notes"])

        for payload in ({"format": "exe", "scope": "case"}, {"format": "json", "scope": "thread"}):
            request = urllib.request.Request(base_url + endpoint, data=json.dumps(payload).encode("utf-8"), method="POST")
            request.add_header("Content-Type", "application/json")
            request.add_header("Cookie", _SESSIONS[base_url]["cookie"])
            request.add_header("X-FK-CSRF", _SESSIONS[base_url]["csrf"])
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                assert error.code == 400
            else:
                raise AssertionError("invalid report export request was accepted")

        old_limit = workbench_module.REPORT_EXPORT_MAX_BYTES
        workbench_module.REPORT_EXPORT_MAX_BYTES = 1
        try:
            request = urllib.request.Request(base_url + endpoint, data=json.dumps({"format": "json", "scope": "case"}).encode("utf-8"), method="POST")
            request.add_header("Content-Type", "application/json")
            request.add_header("Cookie", _SESSIONS[base_url]["cookie"])
            request.add_header("X-FK-CSRF", _SESSIONS[base_url]["csrf"])
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                assert error.code == 413
                assert json.loads(error.read().decode("utf-8"))["error"]["code"] == "REPORT_RESULT_TOO_LARGE"
            else:
                raise AssertionError("oversized report result was not bounded")
        finally:
            workbench_module.REPORT_EXPORT_MAX_BYTES = old_limit
        assert source_path.read_bytes() == source_before
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_workbench_handles_malformed_backend_data_safely(tmp_path: Path):
    case_dir, result = _sample_case(tmp_path)
    server, thread, base_url = _start(case_dir)
    normalized = case_dir / "normalized-events.jsonl"
    original = normalized.read_bytes()
    try:
        normalized.write_bytes(b"not valid jsonl\xff")
        try:
            _request(base_url, f"/api/cases/{result['manifest']['case_id']}/events")
        except urllib.error.HTTPError as error:
            body = json.loads(error.read().decode("utf-8"))
            assert error.code == 500
            assert body["error"]["code"] == "CASE_DATA_INVALID"
        else:
            raise AssertionError("malformed backend data was accepted")
    finally:
        normalized.write_bytes(original)
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_workbench_static_ui_is_local_and_untrusted_content_is_not_interpolated(tmp_path: Path):
    case_dir, _ = _sample_case(tmp_path)
    try:
        WorkbenchServer(("0.0.0.0", 0), case_dir)
    except ValueError as error:
        assert "localhost" in str(error)
    else:
        raise AssertionError("workbench accepted a non-loopback bind address")
    server, thread, base_url = _start(case_dir)
    try:
        with urllib.request.urlopen(base_url + "/", timeout=5) as response:
            page = response.read().decode("utf-8")
        assert response.status == 200
        assert "ForensicKit Workbench" in page
        assert "Evidence graph" in page and "graph-svg" in page and "Assistant" in page
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "Python/" not in response.headers.get("Server", "")
        unsupported = urllib.request.Request(base_url + "/", method="TRACE")
        try:
            urllib.request.urlopen(unsupported, timeout=5)
        except urllib.error.HTTPError as error:
            assert error.code == 405
            assert error.headers["X-Content-Type-Options"] == "nosniff"
            assert "Content-Security-Policy" in error.headers
            assert "Python/" not in error.headers.get("Server", "")
            assert json.loads(error.read())["error"]["code"] == "METHOD_NOT_ALLOWED"
        else:
            raise AssertionError("unsupported HTTP method was accepted")
        for asset in ("/logo-mark.svg", "/favicon.svg"):
            with urllib.request.urlopen(base_url + asset, timeout=5) as logo_response:
                assert logo_response.status == 200
                assert logo_response.headers.get_content_type() == "image/svg+xml"
                assert logo_response.headers["X-Content-Type-Options"] == "nosniff"
                logo = logo_response.read().decode("utf-8")
                assert "<svg" in logo and "<script" not in logo
            assert asset in page
        request = urllib.request.Request(base_url + "/app.js")
        with urllib.request.urlopen(request, timeout=5) as response:
            script = response.read().decode("utf-8")
            content_security_policy = response.headers["Content-Security-Policy"]
        assert content_security_policy
        assert "innerHTML" not in script
        assert "createElementNS" in script and "loadGraph" in script and "runAssistant" in script
        assert "setup-form" in page and "login-form" in page
        assert 'data-theme-choice="light"' in page and 'data-theme-choice="dark"' in page and 'data-theme-choice="system"' in page
        assert "nav-collapse" in page and 'aria-controls="workbench-nav"' in page
        assert 'data-view="reports"' in page and 'id="report-form"' in page
        assert 'value="path" checked disabled' in page and 'value="command_line"' in page and 'value="text"' in page
        assert "fetch(" in script
        assert "forensickit.nav-collapsed" in script and "setNavigationCollapsed" in script
        assert "data-theme-choice" in script and "aria-pressed" in script and ".style." not in script
        assert 'casePath("/reports/export")' in script and "createObjectURL" in script and "innerHTML" not in script
        with urllib.request.urlopen(base_url + "/styles.css", timeout=5) as response:
            styles = response.read().decode("utf-8")
        assert ':root[data-theme="dark"]' in styles and "prefers-color-scheme: dark" in styles
        assert "body.nav-collapsed" in styles and "max-width: 760px" in styles
        assert 'src="/app.js"' in page and "https://" not in page
        blocked = urllib.request.Request(base_url + "/%2e%2e/workbench.py")
        try:
            urllib.request.urlopen(blocked, timeout=5)
        except urllib.error.HTTPError as error:
            assert error.code == 404
        else:
            raise AssertionError("arbitrary static path was served")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_workbench_requires_login_csrf_and_sets_restricted_session_cookie(tmp_path: Path):
    case_dir, result = _sample_case(tmp_path)
    server, thread, base_url = _start(case_dir, authenticate=False)
    try:
        status, auth_state = _request(base_url, "/api/auth/state")
        assert status == 200 and auth_state["data"]["setup_required"]
        assert "setup_code" not in json.dumps(auth_state)
        try:
            _request(base_url, "/api/bootstrap")
        except urllib.error.HTTPError as error:
            body = json.loads(error.read().decode("utf-8"))
            assert error.code == 401 and body["error"]["code"] == "AUTHENTICATION_REQUIRED"
        else:
            raise AssertionError("case data was served without login")

        status, created = _request(base_url, "/api/auth/setup", "POST", {
            "setup_code": server.auth.bootstrap_code,
            "username": "reviewer",
            "password": "ForensicKit test passphrase 2026!",
        })
        assert status == 201
        cookie_header = _SESSIONS[base_url]["cookie"]
        assert cookie_header.startswith("FKSESSION=")
        assert _SESSIONS[base_url]["csrf"] == created["data"]["csrf_token"]

        csrf_missing = urllib.request.Request(base_url + f"/api/cases/{result['manifest']['case_id']}/notes", data=json.dumps({"text": "No token"}).encode("utf-8"), method="POST")
        csrf_missing.add_header("Content-Type", "application/json")
        csrf_missing.add_header("Cookie", cookie_header)
        try:
            urllib.request.urlopen(csrf_missing, timeout=5)
        except urllib.error.HTTPError as error:
            body = json.loads(error.read().decode("utf-8"))
            assert error.code == 403 and body["error"]["code"] == "CSRF_TOKEN_INVALID"
        else:
            raise AssertionError("state change succeeded without a CSRF token")

        assert "csrf_token" not in cookie_header
        assert created["data"]["csrf_token"] not in cookie_header
        # The real cookie attributes are asserted against the wire response by
        # replaying login and inspecting its Set-Cookie header directly.
        login_body = json.dumps({"username": "reviewer", "password": "ForensicKit test passphrase 2026!"}).encode("utf-8")
        login = urllib.request.Request(base_url + "/api/auth/login", data=login_body, method="POST")
        login.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(login, timeout=5) as response:
            set_cookie = response.headers.get("Set-Cookie", "")
            assert "HttpOnly" in set_cookie and "SameSite=Strict" in set_cookie and "Max-Age=1800" in set_cookie

        status, logged_out = _request(base_url, "/api/auth/logout", "POST", {})
        assert status == 200 and logged_out["data"]["logged_out"]
        try:
            _request(base_url, "/api/bootstrap")
        except urllib.error.HTTPError as error:
            assert error.code == 401
        else:
            raise AssertionError("logout did not revoke the session")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
