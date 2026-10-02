"""Local single-analyst authentication and per-user workbench settings."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path


SESSION_IDLE_SECONDS = 30 * 60
SESSION_MAX_SECONDS = 8 * 60 * 60
SETUP_CODE_LIFETIME_SECONDS = 15 * 60
MAX_LOGIN_FAILURES = 5
LOGIN_LOCK_SECONDS = 5 * 60
PASSWORD_SCRYPT_N = 1 << 14
PASSWORD_SCRYPT_R = 8
PASSWORD_SCRYPT_P = 1
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,64}$")
THEMES = {"system", "light", "dark"}


class AuthError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass
class AuthSession:
    username: str
    csrf_token: str
    created_at: float
    last_seen: float


def user_data_directory() -> Path:
    """Return the per-user, non-install application-data directory."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "ForensicKit"
    base = os.environ.get("XDG_STATE_HOME")
    if base:
        return Path(base) / "forensickit"
    return Path.home() / ".local" / "state" / "forensickit"


class AuthManager:
    """One local account, short-lived in-memory sessions, and theme settings.

    ``data_dir`` is injectable for isolated tests; production callers use the
    platform per-user location returned by :func:`user_data_directory`.
    """

    def __init__(
        self,
        data_dir: Path | None = None,
        *,
        clock=time.monotonic,
        session_idle_seconds: int = SESSION_IDLE_SECONDS,
        session_max_seconds: int = SESSION_MAX_SECONDS,
        setup_code_lifetime_seconds: int = SETUP_CODE_LIFETIME_SECONDS,
    ):
        self.data_dir = Path(data_dir or user_data_directory()).expanduser().resolve()
        self.account_path = self.data_dir / "account.json"
        self.settings_path = self.data_dir / "settings.json"
        self._clock = clock
        self.session_idle_seconds = session_idle_seconds
        self.session_max_seconds = session_max_seconds
        self.setup_code_lifetime_seconds = setup_code_lifetime_seconds
        self._lock = threading.RLock()
        self._sessions: dict[str, AuthSession] = {}
        self._login_failures: dict[str, tuple[int, float]] = {}
        self._setup_failures: dict[str, tuple[int, float]] = {}
        self._bootstrap_code: str | None = None
        self._bootstrap_expires = 0.0
        if self._load_account() is None:
            self._rotate_setup_code()

    @property
    def bootstrap_code(self) -> str | None:
        """Secret launch-flow code; never include this value in API responses."""
        with self._lock:
            if self._bootstrap_code and self._clock() >= self._bootstrap_expires:
                self._bootstrap_code = None
            return self._bootstrap_code

    @property
    def setup_required(self) -> bool:
        return self._load_account() is None

    def _rotate_setup_code(self) -> None:
        self._bootstrap_code = secrets.token_urlsafe(24)
        self._bootstrap_expires = self._clock() + self.setup_code_lifetime_seconds

    def _ensure_directory(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if self.data_dir.is_symlink() or not self.data_dir.is_dir():
            raise AuthError("AUTH_STATE_INVALID", "Local account storage is unavailable.", 500)

    def _load_json_file(self, path: Path) -> dict | None:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise AuthError("AUTH_STATE_INVALID", "Local account storage could not be read.", 500) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            raise AuthError("AUTH_STATE_INVALID", "Local account storage is invalid.", 500)
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AuthError("AUTH_STATE_INVALID", "Local account storage could not be read.", 500) from exc
        if not isinstance(value, dict):
            raise AuthError("AUTH_STATE_INVALID", "Local account storage is invalid.", 500)
        return value

    def _load_account(self) -> dict | None:
        value = self._load_json_file(self.account_path)
        if value is None or value.get("setup_required") is True:
            return None
        required = {"format_version", "username", "password_hash", "password_salt", "algorithm"}
        if not required.issubset(value) or value.get("format_version") != 1 or value.get("algorithm") != "scrypt-16384-8-1":
            raise AuthError("AUTH_STATE_INVALID", "Local account storage is invalid; use the documented recovery procedure.", 500)
        if not isinstance(value.get("username"), str) or not USERNAME_PATTERN.fullmatch(value["username"]):
            raise AuthError("AUTH_STATE_INVALID", "Local account storage is invalid; use the documented recovery procedure.", 500)
        try:
            salt = bytes.fromhex(value["password_salt"])
            password_hash = bytes.fromhex(value["password_hash"])
        except (TypeError, ValueError) as exc:
            raise AuthError("AUTH_STATE_INVALID", "Local account storage is invalid; use the documented recovery procedure.", 500) from exc
        if len(salt) != 16 or len(password_hash) != 32:
            raise AuthError("AUTH_STATE_INVALID", "Local account storage is invalid; use the documented recovery procedure.", 500)
        return value

    def _atomic_write(self, path: Path, payload: dict) -> None:
        self._ensure_directory()
        encoded = (json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(prefix=".fk-", suffix=".tmp", dir=self.data_dir, delete=False) as stream:
                temp_path = Path(stream.name)
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.chmod(temp_path, 0o600)
            except OSError:
                # Windows uses the inherited per-user ACL on LocalAppData.
                pass
            os.replace(temp_path, path)
        except OSError as exc:
            raise AuthError("AUTH_STATE_WRITE_FAILED", "Local account storage could not be updated.", 500) from exc
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass

    @staticmethod
    def _validate_username(username: str) -> str:
        if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
            raise AuthError("AUTH_USERNAME_INVALID", "Use a 3–64 character username with letters, numbers, dot, underscore, or hyphen.")
        return username

    @staticmethod
    def _validate_password(password: str) -> str:
        if not isinstance(password, str) or len(password) < 12 or len(password.encode("utf-8")) > 1024:
            raise AuthError("AUTH_PASSWORD_INVALID", "Password must be at least 12 characters and no more than 1024 UTF-8 bytes.")
        return password

    @staticmethod
    def _derive_password(password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=PASSWORD_SCRYPT_N,
            r=PASSWORD_SCRYPT_R,
            p=PASSWORD_SCRYPT_P,
            dklen=32,
        )

    def _new_session(self, username: str) -> tuple[str, AuthSession]:
        now = self._clock()
        session_id = secrets.token_urlsafe(32)
        session = AuthSession(username=username, csrf_token=secrets.token_urlsafe(32), created_at=now, last_seen=now)
        self._sessions[session_id] = session
        return session_id, session

    def create_account(self, code: str, username: str, password: str) -> tuple[str, AuthSession]:
        username = self._validate_username(username)
        password = self._validate_password(password)
        with self._lock:
            if self._load_account() is not None:
                self._bootstrap_code = None
                raise AuthError("AUTH_SETUP_ALREADY_COMPLETE", "Local account setup is already complete.", 409)
            provided_code = code if isinstance(code, str) else ""
            expected_code = self.bootstrap_code or ""
            if not expected_code:
                raise AuthError("AUTH_SETUP_CODE_EXPIRED", "The setup code expired. Restart the local application to display a new code.", 410)
            if not hmac.compare_digest(provided_code.encode("utf-8"), expected_code.encode("utf-8")):
                self._setup_failures["local"] = (self._setup_failures.get("local", (0, 0.0))[0] + 1, self._clock())
                attempts, _ = self._setup_failures["local"]
                if attempts >= MAX_LOGIN_FAILURES:
                    self._bootstrap_code = None
                raise AuthError("AUTH_SETUP_CODE_INVALID", "The setup code was not accepted.", 401)
            salt = secrets.token_bytes(16)
            digest = self._derive_password(password, salt)
            self._atomic_write(self.account_path, {
                "format_version": 1,
                "username": username,
                "algorithm": "scrypt-16384-8-1",
                "password_salt": salt.hex(),
                "password_hash": digest.hex(),
            })
            self._bootstrap_code = None
            self._setup_failures.clear()
            return self._new_session(username)

    def authenticate(self, username: str, password: str, remote_address: str) -> tuple[str, AuthSession]:
        if not isinstance(username, str) or len(username) > 64 or not isinstance(password, str) or len(password.encode("utf-8")) > 1024:
            raise AuthError("AUTH_INVALID_CREDENTIALS", "Username or password was not accepted.", 401)
        key = remote_address
        with self._lock:
            now = self._clock()
            attempts, started = self._login_failures.get(key, (0, now))
            if attempts >= MAX_LOGIN_FAILURES and now - started < LOGIN_LOCK_SECONDS:
                raise AuthError("AUTH_LOGIN_THROTTLED", "Too many sign-in attempts. Wait before trying again.", 429)
            if now - started >= LOGIN_LOCK_SECONDS:
                attempts, started = 0, now
            account = self._load_account()
            match = False
            if account and username.casefold() == account["username"].casefold():
                salt = bytes.fromhex(account["password_salt"])
                supplied = self._derive_password(password, salt)
                match = hmac.compare_digest(supplied, bytes.fromhex(account["password_hash"]))
            else:
                # Spend comparable work when the account name is not a match.
                self._derive_password(password or "invalid", b"ForensicKitDummy!")
            if not match:
                attempts += 1
                self._login_failures[key] = (attempts, started)
                raise AuthError("AUTH_INVALID_CREDENTIALS", "Username or password was not accepted.", 401)
            self._login_failures.pop(key, None)
            return self._new_session(account["username"])

    def resolve_session(self, session_id: str | None) -> tuple[str, AuthSession] | None:
        if not session_id:
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            now = self._clock()
            if now - session.last_seen >= self.session_idle_seconds or now - session.created_at >= self.session_max_seconds:
                self._sessions.pop(session_id, None)
                return None
            session.last_seen = now
            return session_id, session

    def revoke_session(self, session_id: str | None) -> None:
        if session_id:
            with self._lock:
                self._sessions.pop(session_id, None)

    def get_settings(self) -> dict:
        with self._lock:
            try:
                value = self._load_json_file(self.settings_path)
            except AuthError:
                return {"theme": "system"}
            theme = value.get("theme", "system") if value else "system"
            return {"theme": theme if theme in THEMES else "system"}

    def update_settings(self, theme: str) -> dict:
        if theme not in THEMES:
            raise AuthError("SETTINGS_INVALID", "Theme must be system, light, or dark.")
        with self._lock:
            self._atomic_write(self.settings_path, {"format_version": 1, "theme": theme})
        return {"theme": theme}

    def reset_account(self) -> None:
        """Replace only the login record with setup-required state."""
        with self._lock:
            if self.account_path.exists():
                self._atomic_write(self.account_path, {"format_version": 1, "setup_required": True})
            self._sessions.clear()
            self._bootstrap_code = None
            self._rotate_setup_code()
            self._login_failures.clear()
