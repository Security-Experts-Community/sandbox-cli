from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import aiohttp
import pytest

from sandbox_cli.core.config import VMImage
from sandbox_cli.core.exceptions import ScanError
from sandbox_cli.core.reporting import shorten_name
from sandbox_cli.services.scanner.hooks import merge_dll_hooks
from sandbox_cli.services.scanner.images import resolve_scan_images
from sandbox_cli.services.scanner.runner import describe_error, plan_targets
from sandbox_cli.services.scanner.utils import compute_wait_time


class TestShortenName:
    def test_short_name_is_unchanged(self) -> None:
        assert shorten_name("sample.exe") == "sample.exe"

    def test_keeps_extension(self) -> None:
        name = "0123456789abcdef0123456789abcdef.exe"
        short = shorten_name(name)
        assert short.endswith("….exe")
        assert len(short) == 24

    def test_long_suffix_is_not_treated_as_extension(self) -> None:
        short = shorten_name("a" * 30 + ".verylongext")
        assert short.endswith("…")
        assert len(short) == 24


class TestComputeWaitTime:
    def test_explicit_timeout_wins(self) -> None:
        assert compute_wait_time(300, 42) == 42

    def test_short_analysis_gets_bigger_bonus(self) -> None:
        assert compute_wait_time(60) == 60 * 4 + 300

    def test_long_analysis(self) -> None:
        assert compute_wait_time(300) == 300 * 4 + 120


class TestResolveScanImages:
    available: ClassVar[set[VMImage | str]] = {VMImage.WIN10_22H2_X64, VMImage.UBUNTU_JAMMY_X64, "custom-image"}

    def test_platform_alias_expands_to_available_images(self) -> None:
        images, default = resolve_scan_images(self.available, {VMImage.LINUX})
        assert images == {VMImage.UBUNTU_JAMMY_X64}
        assert default == VMImage.UBUNTU_JAMMY_X64

    def test_explicit_and_custom_images(self) -> None:
        images, default = resolve_scan_images(self.available, {"custom-image"})
        assert images == {"custom-image"}
        assert default == "custom-image"

    def test_unavailable_image_raises(self) -> None:
        with pytest.raises(ScanError):
            resolve_scan_images(self.available, {VMImage.WIN7_SP1_X64})

    def test_unsupported_platform_raises(self) -> None:
        with pytest.raises(ScanError):
            resolve_scan_images({VMImage.UBUNTU_JAMMY_X64}, {VMImage.WINDOWS})


class TestPlanTargets:
    def test_single_file_single_image(self, tmp_path: Path) -> None:
        [target] = plan_targets([Path("a.exe")], ["img1"], tmp_path)
        assert (target.image, target.out_dir, target.idx) == ("img1", tmp_path / "img1", "1/1")

    def test_single_file_many_images(self, tmp_path: Path) -> None:
        targets = plan_targets([Path("a.exe")], ["img2", "img1"], tmp_path)
        assert [(t.image, t.out_dir.name, t.idx) for t in targets] == [("img1", "img1", "1/2"), ("img2", "img2", "2/2")]

    def test_many_files_many_images(self, tmp_path: Path) -> None:
        targets = plan_targets([Path("a.exe"), Path("b.dll")], ["img1", "img2"], tmp_path)
        assert [t.out_dir.relative_to(tmp_path) for t in targets] == [
            Path("a/img1"),
            Path("b/img1"),
            Path("a/img2"),
            Path("b/img2"),
        ]
        assert [t.idx for t in targets] == ["1/4", "2/4", "3/4", "4/4"]
        assert all(t.out_dir.is_dir() for t in targets)


class TestDescribeError:
    def test_known_errors(self) -> None:
        assert describe_error(ScanError("bad")) == "bad"
        assert describe_error(TimeoutError()).startswith("unexpected error • TimeoutError")
        assert describe_error(aiohttp.ClientConnectionError("refused")) == "connection error • refused"
        assert describe_error(aiohttp.SocketTimeoutError()) == "got timeout while downloading results"


class TestDllHooks:
    def test_merge_prefixes_and_deduplicates(self, tmp_path: Path) -> None:
        (tmp_path / "kernel32.txt").write_text(
            "# comment\n\nCreateFileW,log\nCreateFileW,log\nSysWOW64,ReadFile,log+stack,arg1\n"
        )
        merged = merge_dll_hooks(tmp_path).decode().splitlines()
        assert len(merged) == 2
        assert merged[0] == "kernel32.dll,CreateFileW,log"
        assert merged[1].startswith("SysWOW64\\kernel32.dll,")

    @pytest.mark.parametrize(
        "hook",
        [
            "RtlAllocateHeap,log",  # slow function
            "CreateFileW",  # no strategy
            "CreateFileW,unknown",  # bad strategy
            "CreateFileW,log,,arg",  # empty argument
            "CreateFileW,no-retval",  # no strategy after no-retval
        ],
    )
    def test_invalid_hooks_are_rejected(self, tmp_path: Path, hook: str) -> None:
        (tmp_path / "kernel32.txt").write_text("# header\n" + hook + "\n")
        with pytest.raises(ScanError, match=r"kernel32\.txt:2: "):
            merge_dll_hooks(tmp_path)

    def test_empty_directory_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(ScanError, match="No DLL hooks"):
            merge_dll_hooks(tmp_path)


class TestUniqueDirs:
    def test_same_stem_uses_full_name(self, tmp_path: Path) -> None:
        targets = plan_targets([Path("a.exe"), Path("a.dll"), Path("b.js")], ["img"], tmp_path)
        assert [t.out_dir.relative_to(tmp_path) for t in targets] == [
            Path("a.exe/img"),
            Path("a.dll/img"),
            Path("b/img"),
        ]

    def test_same_name_in_different_folders(self, tmp_path: Path) -> None:
        targets = plan_targets([Path("x86/payload.dll"), Path("x64/payload.dll")], ["img"], tmp_path)
        assert [t.out_dir.relative_to(tmp_path) for t in targets] == [
            Path("payload.dll/img"),
            Path("payload.dll_1/img"),
        ]

    def test_rescan_zips_with_the_same_name(self) -> None:
        from sandbox_cli.services.scanner.rescan import _out_dir_names

        traces = [Path("a/sandbox_logs.zip"), Path("b/sandbox_logs.zip"), Path("c/raw")]
        assert _out_dir_names(traces) == ["sandbox_logs", "sandbox_logs_1", "rescan_3"]


def test_non_utf8_dll_hooks_are_a_scan_error(tmp_path: Path) -> None:
    (tmp_path / "kernel32.txt").write_bytes(b"CreateFileW,log\n\xff\xfe\n")
    with pytest.raises(ScanError, match=r"Can't read .*kernel32\.txt"):
        merge_dll_hooks(tmp_path)
