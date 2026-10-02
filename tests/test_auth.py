import json
from pathlib import Path

from forensickit.auth import AuthError, AuthManager


def test_local_account_setup_password_storage_and_reset_are_scoped(tmp_path: Path):
    manager = AuthManager(tmp_path / "profile")
    setup_code = manager.bootstrap_code
    assert setup_code and len(setup_code) >= 32
    try:
        manager.create_account("wrong-code", "reviewer", "A sufficiently long passphrase!")
    except AuthError as error:
        assert error.code == "AUTH_SETUP_CODE_INVALID"
    else:
        raise AssertionError("an invalid first-run code created an account")

    session_id, session = manager.create_account(setup_code, "reviewer", "A sufficiently long passphrase!")
    assert session.username == "reviewer"
    assert manager.bootstrap_code is None
    assert manager.resolve_session(session_id)
    saved = json.loads(manager.account_path.read_text(encoding="utf-8"))
    serialized = json.dumps(saved)
    assert "scrypt-16384-8-1" == saved["algorithm"]
    assert "A sufficiently long passphrase!" not in serialized
    assert len(saved["password_salt"]) == 32 and len(saved["password_hash"]) == 64
    try:
        manager.create_account(setup_code, "other", "A different passphrase 123!")
    except AuthError as error:
        assert error.code == "AUTH_SETUP_ALREADY_COMPLETE"
    else:
        raise AssertionError("the single local account was overwritten")

    unrelated_case = tmp_path / "case" / "manifest.json"
    unrelated_case.parent.mkdir()
    unrelated_case.write_text("synthetic case marker", encoding="utf-8")
    manager.reset_account()
    assert manager.setup_required and manager.bootstrap_code
    assert unrelated_case.read_text(encoding="utf-8") == "synthetic case marker"
    assert manager.resolve_session(session_id) is None


def test_local_login_hashing_throttle_and_short_lived_sessions(tmp_path: Path):
    now = [100.0]
    manager = AuthManager(tmp_path / "profile", clock=lambda: now[0], session_idle_seconds=10, session_max_seconds=25)
    setup_code = manager.bootstrap_code
    manager.create_account(setup_code, "analyst.1", "correct horse battery staple 2026")
    assert manager.authenticate("ANALYST.1", "correct horse battery staple 2026", "127.0.0.1")[1].username == "analyst.1"

    for _ in range(5):
        try:
            manager.authenticate("analyst.1", "not the password", "127.0.0.1")
        except AuthError as error:
            assert error.code == "AUTH_INVALID_CREDENTIALS"
        else:
            raise AssertionError("an invalid password authenticated")
    try:
        manager.authenticate("analyst.1", "not the password", "127.0.0.1")
    except AuthError as error:
        assert error.code == "AUTH_LOGIN_THROTTLED" and error.status == 429
    else:
        raise AssertionError("login throttling did not activate")

    session_id, _ = manager.authenticate("analyst.1", "correct horse battery staple 2026", "127.0.0.2")
    now[0] += 11
    assert manager.resolve_session(session_id) is None
    session_id, _ = manager.authenticate("analyst.1", "correct horse battery staple 2026", "127.0.0.2")
    now[0] += 26
    assert manager.resolve_session(session_id) is None


def test_per_user_settings_persist_without_storing_session_tokens(tmp_path: Path):
    data_dir = tmp_path / "profile"
    manager = AuthManager(data_dir)
    manager.update_settings("dark")
    assert AuthManager(data_dir).get_settings() == {"theme": "dark"}
    try:
        manager.update_settings("ultraviolet")
    except AuthError as error:
        assert error.code == "SETTINGS_INVALID"
    else:
        raise AssertionError("an unsupported theme was persisted")


def test_setup_code_expires_and_failed_guesses_consume_it(tmp_path: Path):
    now = [0.0]
    expired = AuthManager(tmp_path / "expired", clock=lambda: now[0], setup_code_lifetime_seconds=10)
    now[0] = 11
    try:
        expired.create_account(expired.bootstrap_code or "", "reviewer", "A sufficiently long passphrase!")
    except AuthError as error:
        assert error.code == "AUTH_SETUP_CODE_EXPIRED"
    else:
        raise AssertionError("an expired setup code was accepted")

    limited = AuthManager(tmp_path / "limited", clock=lambda: now[0])
    for _ in range(5):
        try:
            limited.create_account("incorrect", "reviewer", "A sufficiently long passphrase!")
        except AuthError as error:
            assert error.code == "AUTH_SETUP_CODE_INVALID"
    assert limited.bootstrap_code is None
