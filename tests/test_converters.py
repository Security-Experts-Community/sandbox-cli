from __future__ import annotations

from pathlib import Path

import pytest

from sandbox_cli.cli._converters import files_path_resolver
from sandbox_cli.core.exceptions import ScanError


def test_folder_is_expanded_to_files_only(tmp_path: Path) -> None:
    (tmp_path / "nested").mkdir()
    (tmp_path / "a.exe").touch()
    (tmp_path / "nested" / "b.dll").touch()

    assert [p.name for p in files_path_resolver([tmp_path])] == ["a.exe", "b.dll"]


def test_duplicates_are_collapsed(tmp_path: Path) -> None:
    sample = tmp_path / "a.exe"
    sample.touch()
    assert files_path_resolver([sample, sample, tmp_path]) == [sample.resolve()]


def test_all_missing_paths_are_reported(tmp_path: Path) -> None:
    (tmp_path / "a.exe").touch()
    with pytest.raises(ScanError, match=r"missing1\.exe.*missing2\.exe"):
        files_path_resolver([tmp_path / "missing1.exe", tmp_path / "a.exe", tmp_path / "missing2.exe"])


def test_empty_folder_fails(tmp_path: Path) -> None:
    with pytest.raises(ScanError, match="Nothing to scan"):
        files_path_resolver([tmp_path])
