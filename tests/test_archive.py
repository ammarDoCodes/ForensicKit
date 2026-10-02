from pathlib import Path
import stat
import zipfile

from forensickit.analysis import analyze_case, load_case
from forensickit.archive import ArchiveLimits, ArchiveRejected, extract_archive


def test_archive_import_is_read_only_and_deterministic(tmp_path: Path):
    archive = tmp_path / "evidence.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("events.jsonl", '{"event_type":"logon","timestamp":"2026-01-01T00:00:00Z","host":"h"}\n')
    before = archive.read_bytes()
    result = analyze_case(tmp_path / "case", archive)
    assert result["events"]
    assert result["manifest"]["archive"]["file_count"] == 1
    assert archive.read_bytes() == before


def test_archive_traversal_and_ratio_rejection(tmp_path: Path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("../../outside.jsonl", "x")
    try:
        extract_archive(archive, tmp_path / "out")
    except ArchiveRejected as error:
        assert error.code == "ARCHIVE_PATH_TRAVERSAL"
    else:
        raise AssertionError("archive traversal was accepted")

    drive_archive = tmp_path / "drive.zip"
    with zipfile.ZipFile(drive_archive, "w") as output:
        output.writestr("C:/outside.jsonl", "x")
    try:
        extract_archive(drive_archive, tmp_path / "drive-out")
    except ArchiveRejected as error:
        assert error.code == "ARCHIVE_PATH_TRAVERSAL"
    else:
        raise AssertionError("drive-qualified archive path was accepted")

    symlink_archive = tmp_path / "symlink.zip"
    link = zipfile.ZipInfo("link.jsonl")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(symlink_archive, "w") as output:
        output.writestr(link, "outside.jsonl")
    try:
        extract_archive(symlink_archive, tmp_path / "symlink-out")
    except ArchiveRejected as error:
        assert error.code == "ARCHIVE_LINK_REJECTED"
    else:
        raise AssertionError("archive symlink was accepted")

    bomb = tmp_path / "ratio.zip"
    with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("large.txt", "A" * 100_000)
    try:
        extract_archive(bomb, tmp_path / "ratio-out", ArchiveLimits(max_compression_ratio=2))
    except ArchiveRejected as error:
        assert error.code == "ARCHIVE_COMPRESSION_RATIO"
    else:
        raise AssertionError("archive compression ratio was accepted")

    limits_archive = tmp_path / "limits.zip"
    with zipfile.ZipFile(limits_archive, "w") as output:
        output.writestr("one.txt", "123")
        output.writestr("two.txt", "456")
    try:
        extract_archive(limits_archive, tmp_path / "count-out", ArchiveLimits(max_files=1))
    except ArchiveRejected as error:
        assert error.code == "ARCHIVE_FILE_COUNT"
    else:
        raise AssertionError("archive file-count limit was not enforced")
    try:
        extract_archive(limits_archive, tmp_path / "size-out", ArchiveLimits(max_extracted_bytes=2))
    except ArchiveRejected as error:
        assert error.code == "ARCHIVE_EXTRACTED_SIZE"
    else:
        raise AssertionError("archive extracted-size limit was not enforced")
    try:
        extract_archive(limits_archive, tmp_path / "input-size-out", ArchiveLimits(max_archive_bytes=1))
    except ArchiveRejected as error:
        assert error.code == "ARCHIVE_INPUT_SIZE"
    else:
        raise AssertionError("archive input-size limit was not enforced")
