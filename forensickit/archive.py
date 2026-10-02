from __future__ import annotations

import shutil
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .constants import SCHEMA_VERSION
from .util import safe_archive_member, safe_relative_path, sha256_bytes


@dataclass(frozen=True)
class ArchiveLimits:
    max_archive_bytes: int = 50 * 1024 * 1024
    max_depth: int = 8
    max_files: int = 1000
    max_extracted_bytes: int = 200 * 1024 * 1024
    max_compression_ratio: float = 100.0


class ArchiveRejected(ValueError):
    def __init__(self, code: str, message: str, member: str | None = None):
        super().__init__(message)
        self.code = code
        self.member = member


def is_supported_archive(path: Path) -> bool:
    try:
        return zipfile.is_zipfile(path) or tarfile.is_tarfile(path)
    except (OSError, tarfile.TarError):
        return False


def _diagnostic(code: str, message: str, source_file_id: str, member: str | None = None) -> dict:
    result = {"schema_version": SCHEMA_VERSION, "severity": "warning", "code": code, "message": message, "source_file_id": source_file_id, "source_locator": member or "archive"}
    if member is not None:
        result["archive_member"] = member
    return result


def _member_target(destination: Path, name: str, max_depth: int) -> Path:
    if not safe_archive_member(name):
        raise ArchiveRejected("ARCHIVE_PATH_TRAVERSAL", "Archive member path is absolute, drive-qualified, or escapes the archive root.", name)
    normalized = name.replace("\\", "/")
    depth = len([part for part in PurePosixPath(normalized).parts if part not in (".", "")])
    if depth > max_depth:
        raise ArchiveRejected("ARCHIVE_MEMBER_DEPTH", f"Archive member exceeds maximum depth {max_depth}.", name)
    target = (destination / PurePosixPath(normalized)).resolve()
    try:
        target.relative_to(destination.resolve())
    except ValueError as exc:
        raise ArchiveRejected("ARCHIVE_PATH_TRAVERSAL", "Archive member resolves outside the extraction root.", name) from exc
    return target


def _zip_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode) or bool(info.external_attr & 0x40000000)


def _check_ratio(compressed: int, uncompressed: int, limit: float, member: str) -> None:
    if uncompressed <= 0:
        return
    ratio = float("inf") if compressed <= 0 else uncompressed / compressed
    if ratio > limit:
        raise ArchiveRejected("ARCHIVE_COMPRESSION_RATIO", f"Archive member compression ratio exceeds {limit:g}:1.", member)


def _copy_bounded(source, target, remaining: int) -> int:
    written = 0
    with target.open("wb") as output:
        while True:
            chunk = source.read(min(1024 * 1024, remaining - written + 1))
            if not chunk:
                break
            written += len(chunk)
            if written > remaining:
                raise ArchiveRejected("ARCHIVE_EXTRACTED_SIZE", "Archive extraction exceeds the configured size limit.")
            output.write(chunk)
    return written


def _validate_member_depth(name: str, limits: ArchiveLimits) -> None:
    depth = len([part for part in PurePosixPath(name.replace("\\", "/")).parts if part not in (".", "")])
    if depth > limits.max_depth:
        raise ArchiveRejected("ARCHIVE_MEMBER_DEPTH", f"Archive member exceeds maximum depth {limits.max_depth}.", name)


def extract_archive(archive_path: Path, destination: Path, limits: ArchiveLimits | None = None, archive_depth: int = 0) -> tuple[list[dict], dict]:
    """Safely extract one archive level. No links or nested archives are followed."""
    limits = limits or ArchiveLimits()
    archive_path = archive_path.resolve()
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if archive_path.stat().st_size > limits.max_archive_bytes:
        raise ArchiveRejected("ARCHIVE_INPUT_SIZE", f"Archive exceeds the maximum input size {limits.max_archive_bytes} bytes.")
    source_file_id = "archive:" + sha256_bytes(archive_path.read_bytes())[:16]
    diagnostics: list[dict] = []
    extracted_bytes = 0
    extracted_files = 0
    if archive_depth >= limits.max_depth:
        raise ArchiveRejected("ARCHIVE_DEPTH", f"Archive nesting exceeds maximum depth {limits.max_depth}.")

    try:
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path) as archive:
                infos = sorted(archive.infolist(), key=lambda info: info.filename.replace("\\", "/").casefold())
                for info in infos:
                    name = info.filename
                    try:
                        _validate_member_depth(name, limits)
                        target = _member_target(destination, name, limits.max_depth)
                        if _zip_is_symlink(info):
                            raise ArchiveRejected("ARCHIVE_LINK_REJECTED", "Symbolic-link or reparse-point archive member rejected.", name)
                        if info.is_dir():
                            target.mkdir(parents=True, exist_ok=True)
                            continue
                        if extracted_files >= limits.max_files:
                            raise ArchiveRejected("ARCHIVE_FILE_COUNT", f"Archive exceeds maximum extracted file count {limits.max_files}.", name)
                        _check_ratio(info.compress_size, info.file_size, limits.max_compression_ratio, name)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        extracted_bytes += _copy_bounded(archive.open(info, "r"), target, limits.max_extracted_bytes - extracted_bytes)
                        extracted_files += 1
                    except ArchiveRejected as exc:
                        diagnostics.append(_diagnostic(exc.code, str(exc), source_file_id, exc.member or name))
                        raise
        elif tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path, "r:*") as archive:
                members = sorted(archive.getmembers(), key=lambda member: member.name.replace("\\", "/").casefold())
                total_member_size = sum(max(0, member.size) for member in members if member.isfile())
                _check_ratio(archive_path.stat().st_size, total_member_size, limits.max_compression_ratio, "archive")
                for member in members:
                    name = member.name
                    try:
                        _validate_member_depth(name, limits)
                        target = _member_target(destination, name, limits.max_depth)
                        if member.issym() or member.islnk() or (getattr(member, "type", b"") not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, b"0", b"5")):
                            raise ArchiveRejected("ARCHIVE_LINK_REJECTED", "Symbolic-link, hard-link, or special archive member rejected.", name)
                        if member.isdir():
                            target.mkdir(parents=True, exist_ok=True)
                            continue
                        if not member.isfile():
                            raise ArchiveRejected("ARCHIVE_SPECIAL_FILE", "Special archive member rejected.", name)
                        if extracted_files >= limits.max_files:
                            raise ArchiveRejected("ARCHIVE_FILE_COUNT", f"Archive exceeds maximum extracted file count {limits.max_files}.", name)
                        if member.size > limits.max_extracted_bytes - extracted_bytes:
                            raise ArchiveRejected("ARCHIVE_EXTRACTED_SIZE", "Archive extraction exceeds the configured size limit.", name)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        source = archive.extractfile(member)
                        if source is None:
                            raise ArchiveRejected("ARCHIVE_MEMBER_READ", "Archive member could not be read.", name)
                        extracted_bytes += _copy_bounded(source, target, limits.max_extracted_bytes - extracted_bytes)
                        extracted_files += 1
                    except ArchiveRejected as exc:
                        diagnostics.append(_diagnostic(exc.code, str(exc), source_file_id, exc.member or name))
                        raise
        else:
            raise ArchiveRejected("UNSUPPORTED_ARCHIVE", "Input is not a supported ZIP or TAR archive.")
    except (zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
        if isinstance(exc, ArchiveRejected):
            raise
        raise ArchiveRejected("ARCHIVE_READ_ERROR", f"Archive could not be safely read: {exc}") from exc
    return diagnostics, {"source_file_id": source_file_id, "file_count": extracted_files, "extracted_bytes": extracted_bytes, "archive_depth": archive_depth}
