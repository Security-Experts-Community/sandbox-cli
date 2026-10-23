from __future__ import annotations

import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from ptsandbox.models import EngineSubsystem, SandboxOptionsAdvanced, VNCMode

from sandbox_cli.core.exceptions import ScanError
from sandbox_cli.services.downloader import _plan_run_dirs, _sandbox_runs
from sandbox_cli.services.scanner.advanced import _find_archives, archive_scan_options
from sandbox_cli.services.scanner.archives import is_archive
from sandbox_cli.services.scanner.requests import AdvancedScanRequest
from tests.test_unpack import _make_logs


def _zip(path: Path, names: list[str]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name in names:
            zf.writestr(name, b"x")
    return path


class TestIsArchive:
    def test_plain_zip(self, tmp_path: Path) -> None:
        assert is_archive(_zip(tmp_path / "sample", ["evil.exe"]))

    @pytest.mark.parametrize("marker", ["[Content_Types].xml", "AndroidManifest.xml", "META-INF/MANIFEST.MF"])
    def test_zip_containers_are_not_archives(self, tmp_path: Path, marker: str) -> None:
        assert not is_archive(_zip(tmp_path / "doc", [marker, "word/document.xml"]))

    @pytest.mark.parametrize(
        "head",
        [b"7z\xbc\xaf\x27\x1c\x00\x04", b"Rar!\x1a\x07\x01\x00", b"\x1f\x8b\x08\x00", b"MSCF\x00\x00"],
    )
    def test_signatures(self, tmp_path: Path, head: bytes) -> None:
        (tmp_path / "f").write_bytes(head + b"\x00" * 300)
        assert is_archive(tmp_path / "f")

    def test_regular_files(self, tmp_path: Path) -> None:
        (tmp_path / "a.sh").write_text("#!/bin/sh\necho hi\n")
        (tmp_path / "b.exe").write_bytes(b"MZ" + b"\x00" * 300)
        assert not is_archive(tmp_path / "a.sh")
        assert not is_archive(tmp_path / "b.exe")


def test_archive_scan_options_keep_vm_settings() -> None:
    options = SandboxOptionsAdvanced(
        image_id="ubuntu-jammy-x64", analysis_duration=60, custom_command="sh {file}", mitm_enabled=False
    )
    options.debug_options["rules_url"] = "uri-rules"

    full = archive_scan_options(options)

    assert full.passwords_for_unpack == ["infected"]
    assert full.sandbox.image_id == "ubuntu-jammy-x64"
    assert full.sandbox.analysis_duration == 60
    assert full.sandbox.custom_command == "sh {file}"
    assert full.sandbox.mitm_enabled is False
    assert full.sandbox.debug_options["rules_url"] == "uri-rules"


class TestFindArchives:
    @staticmethod
    def _request(tmp_path: Path, **kwargs: object) -> AdvancedScanRequest:
        files = [_zip(tmp_path / "a.zip", ["x.exe"]), tmp_path / "b.exe"]
        files[1].write_bytes(b"MZ")
        return AdvancedScanRequest(key_name="main", out_dir=tmp_path, files=files, images=set(), **kwargs)  # type: ignore[arg-type]

    def test_without_flag_archives_are_not_routed(self, tmp_path: Path) -> None:
        assert _find_archives(self._request(tmp_path)) == set()

    def test_with_flag(self, tmp_path: Path) -> None:
        assert _find_archives(self._request(tmp_path, unpack_archives=True)) == {tmp_path / "a.zip"}

    def test_conflicting_flags(self, tmp_path: Path) -> None:
        request = self._request(tmp_path, unpack_archives=True, vnc_mode=VNCMode.FULL, disable_clicker=True)
        with pytest.raises(
            ScanError, match=r"^a\.zip: --disable-clicker, --vnc-mode don't work with --unpack-archives"
        ):
            _find_archives(request)


def _run(name: str, image: str, children: list[SimpleNamespace] | None = None) -> SimpleNamespace:
    result = SimpleNamespace(
        engine_subsystem=EngineSubsystem.SANDBOX,
        details=SimpleNamespace(sandbox=SimpleNamespace(image=SimpleNamespace(image_id=image))),
    )
    return SimpleNamespace(
        file_info=SimpleNamespace(file_path=name, sha256="f" * 64),
        engine_results=[result] if image else [],
        artifacts=children,
    )


def test_runs_of_an_archive_get_their_own_dirs(tmp_path: Path) -> None:
    archive = _run("bundle.zip", "", children=[_run("a.exe", "win10"), _run("b.exe", "win10"), _run("a.exe", "win10")])

    dirs = [out for out, _ in _plan_run_dirs(tmp_path / "win10", list(_sandbox_runs([archive])))]

    assert dirs == [tmp_path / "win10" / "a.exe", tmp_path / "win10" / "b.exe", tmp_path / "win10" / "a.exe_1"]


def test_single_run_keeps_the_image_dir(tmp_path: Path) -> None:
    dirs = [out for out, _ in _plan_run_dirs(tmp_path / "win10", list(_sandbox_runs([_run("a.exe", "win10")])))]
    assert dirs == [tmp_path / "win10"]


def test_unpack_results_finds_nested_folders(tmp_path: Path) -> None:
    from sandbox_cli.services.unpack import unpack_results

    _make_logs(tmp_path / "win10" / "a.exe")
    _make_logs(tmp_path / "win10" / "b.exe")

    unpacked = unpack_results(tmp_path)

    assert unpacked == [tmp_path / "win10" / "a.exe", tmp_path / "win10" / "b.exe"]
    assert (tmp_path / "win10" / "b.exe" / "correlated" / "malware.log").exists()
