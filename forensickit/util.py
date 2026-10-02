from __future__ import annotations
import hashlib, json, re
from pathlib import PurePosixPath
from typing import Any

def sha256_bytes(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
def sha256_text(value: str) -> str: return sha256_bytes(value.encode("utf-8"))
def stable_json(value: Any) -> str: return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
def stable_id(prefix: str, *parts: object, length: int = 16) -> str: return f"{prefix}-{sha256_text('\\x1f'.join(stable_json(part) for part in parts))[:length]}"
def clean_text(value: Any) -> str | None:
    if value is None: return None
    text = str(value).strip()
    return text if text else None
def normalize_path(value: Any) -> str | None:
    text = clean_text(value)
    if not text: return None
    return re.sub(r"\\+", lambda _: "\\", text.replace("/", "\\")).casefold()
def normalize_identifier(value: Any) -> str | None:
    text = clean_text(value)
    return text.casefold() if text else None
def safe_relative_path(root, candidate) -> str:
    try: relative = candidate.resolve().relative_to(root.resolve())
    except ValueError as exc: raise ValueError("path escapes the case boundary") from exc
    return PurePosixPath(relative.as_posix()).as_posix()

def is_reparse_point(path) -> bool:
    try:
        attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
        return bool(attributes & 0x400)
    except OSError:
        return True

def safe_archive_member(name: str) -> bool:
    if not name or "\x00" in name: return False
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return not path.is_absolute() and not (len(normalized) >= 2 and normalized[1] == ":") and ".." not in path.parts
