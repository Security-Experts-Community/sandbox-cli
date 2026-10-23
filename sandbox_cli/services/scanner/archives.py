from __future__ import annotations

import zipfile
from pathlib import Path

__all__ = ["is_archive"]

_SIGNATURES: tuple[tuple[int, bytes], ...] = (
    (0, b"7z\xbc\xaf\x27\x1c"),
    (0, b"Rar!\x1a\x07"),
    (0, b"\x1f\x8b"),  # gzip
    (0, b"BZh"),
    (0, b"\xfd7zXZ\x00"),
    (0, b"MSCF"),  # cab
    (257, b"ustar"),  # tar
)
_ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06")

# zip containers that are documents or packages rather than archives
_ZIP_CONTAINER_MARKERS = frozenset({"[Content_Types].xml", "AndroidManifest.xml", "META-INF/MANIFEST.MF", "mimetype"})


def _is_plain_zip(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return False
    return not _ZIP_CONTAINER_MARKERS.intersection(names)


def is_archive(path: Path) -> bool:
    """
    Whether ``path`` is an archive by its signature (zip, 7z, rar, gzip, bzip2, xz, cab, tar).

    Office documents, JARs and APKs are zip files too, but not archives here.
    """
    try:
        with open(path, "rb") as fd:
            head = fd.read(262)
    except OSError:
        return False

    if head.startswith(_ZIP_SIGNATURES):
        return _is_plain_zip(path)
    return any(head[offset : offset + len(magic)] == magic for offset, magic in _SIGNATURES)
