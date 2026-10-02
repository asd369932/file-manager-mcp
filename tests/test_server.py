"""file-manager-mcp 的安全边界测试。"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from file_manager_mcp.server import (  # noqa: E402
    list_dir,
    read_file,
    search,
    write_file,
)


@pytest.fixture()
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("MCP_FILE_ROOT", str(tmp_path))
    (tmp_path / "hello.txt").write_text("line one\nline two\nline three\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "nested.py").write_text("def foo():\n    return 42\n")
    return tmp_path


class TestListDir:
    def test_lists_entries(self, root: Path) -> None:
        out = json.loads(list_dir(str(root)))
        names = [i["name"] for i in out["items"]]
        assert "hello.txt" in names
        assert "sub/" in names  # 目录带斜杠后缀

    def test_pattern_filter(self, root: Path) -> None:
        out = json.loads(list_dir(str(root), pattern="*.txt"))
        assert out["count"] == 1
        assert out["items"][0]["name"] == "hello.txt"

    def test_outside_root_rejected(self, root: Path, tmp_path: Path) -> None:
        out = list_dir("/etc")
        assert out.startswith("[拒绝]")

    def test_traversal_rejected(self, root: Path) -> None:
        out = list_dir(str(root / ".." / ".."))
        assert out.startswith("[拒绝]")

    def test_not_a_dir(self, root: Path) -> None:
        out = list_dir(str(root / "hello.txt"))
        assert "[错误]" in out


class TestReadFile:
    def test_reads_with_line_numbers(self, root: Path) -> None:
        out = read_file(str(root / "hello.txt"))
        assert "line one" in out
        assert "1\tline one" in out  # 行号从 1 开始

    def test_offset_and_limit(self, root: Path) -> None:
        out = read_file(str(root / "hello.txt"), offset=2, limit=1)
        assert "line two" in out
        assert "line three" not in out

    def test_binary_detected(self, root: Path) -> None:
        p = root / "bin.dat"
        p.write_bytes(b"\x00\x01\x02" * 100)
        out = read_file(str(p))
        assert "[二进制]" in out

    def test_too_large_rejected(self, root: Path) -> None:
        p = root / "big.txt"
        p.write_text("x" * (1024 * 1024 + 10))
        out = read_file(str(p))
        assert "[拒绝]" in out
        assert "上限" in out

    def test_outside_root_rejected(self, root: Path) -> None:
        out = read_file("/etc/passwd")
        assert out.startswith("[拒绝]")

    def test_missing(self, root: Path) -> None:
        out = read_file(str(root / "nope.txt"))
        assert "[未找到]" in out

    def test_directory_hint(self, root: Path) -> None:
        out = read_file(str(root / "sub"))
        assert "list_dir" in out


class TestWriteFile:
    def test_write_and_read_back(self, root: Path) -> None:
        out = write_file(str(root / "new.txt"), "content here")
        assert "[成功]" in out
        assert (root / "new.txt").read_text() == "content here"

    def test_append(self, root: Path) -> None:
        write_file(str(root / "a.txt"), "first\n")
        write_file(str(root / "a.txt"), "second\n", append=True)
        assert (root / "a.txt").read_text() == "first\nsecond\n"

    def test_creates_parent_dirs(self, root: Path) -> None:
        write_file(str(root / "deep" / "nested" / "f.txt"), "x")
        assert (root / "deep" / "nested" / "f.txt").exists()

    def test_outside_root_rejected(self, root: Path, tmp_path: Path) -> None:
        out = write_file(str(tmp_path.parent / "escape.txt"), "nope")
        assert out.startswith("[拒绝]")

    def test_write_disabled(self, root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MCP_WRITE_ENABLED", "0")
        out = write_file(str(root / "x.txt"), "y")
        assert "[拒绝]" in out
        assert not (root / "x.txt").exists()

    def test_symlink_escape_rejected(self, root: Path, tmp_path: Path) -> None:
        """根目录内的软链指向根目录外 —— resolve 后越界,必须拒绝。"""
        outside = tmp_path.parent / "outside-target.txt"
        outside.write_text("secret")
        link = root / "escape-link"
        try:
            os.symlink(outside, link)
        except OSError:
            pytest.skip("此环境不支持符号链接")
        assert read_file(str(link)).startswith("[拒绝]")
        assert write_file(str(link), "overwrite").startswith("[拒绝]")


class TestSearch:
    def test_glob_only(self, root: Path) -> None:
        out = json.loads(search(str(root), name_glob="*.txt"))
        assert any("hello.txt" in r["path"] for r in out["results"])

    def test_content_regex(self, root: Path) -> None:
        out = json.loads(search(str(root), name_glob="*.py", content_regex=r"return \d+"))
        assert out["count"] == 1
        assert out["results"][0]["matches"][0]["line"] == 2

    def test_no_match(self, root: Path) -> None:
        out = json.loads(search(str(root), content_regex="zzz_no_such_string"))
        assert out["count"] == 0

    def test_bad_regex(self, root: Path) -> None:
        out = search(str(root), content_regex="([unclosed")
        assert "[正则错误]" in out

    def test_skips_binary_in_content_search(self, root: Path) -> None:
        (root / "b.bin").write_bytes(b"\x00\x01foo\x02")
        out = json.loads(search(str(root), content_regex="foo"))
        assert out["binary_skipped"] >= 1

    def test_outside_root_rejected(self, root: Path) -> None:
        assert search("/etc").startswith("[拒绝]")

    def test_max_results_capped(self, root: Path) -> None:
        for i in range(30):
            (root / f"f{i:02d}.txt").write_text("x")
        out = json.loads(search(str(root), name_glob="*.txt", max_results=5))
        assert out["count"] == 5
        assert out["truncated"] is True
