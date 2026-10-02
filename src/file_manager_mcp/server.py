"""file-manager-mcp — 给 AI 一个安全边界的文件系统工具箱。

四个工具,全部限制在配置的根目录内:
- list_dir: 列目录(名称/类型/大小/修改时间)
- read_file: 读文本(自动探测二进制、超长截断)
- write_file: 写文本(仅限根目录内;可 append)
- search: 按文件名 glob + 按内容正则搜索

安全边界:
- 所有路径先 resolve() 再做前缀校验,符号链接会被展开,防止 ../ 与 symlink 逃逸
- read/write 各有限制:读 1MB / 写 5MB,超出即拒绝而不是截断后继续写
- 写操作默认关闭?否 —— 靠"仅根目录内"约束;想纯只读把 MCP_WRITE_ENABLED=0
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer

server = MCPServer(
    name="file-manager-mcp",
    title="File Manager",
    version="0.1.0",
    instructions=(
        "File operations confined to the configured root directory. "
        "Paths are resolved (symlinks expanded) before validation, so ../ and "
        "symlink escapes are rejected. Read before write; list_dir first when "
        "exploring an unfamiliar tree."
    ),
)

MAX_READ_BYTES = 1024 * 1024          # 1 MB
MAX_WRITE_BYTES = 5 * 1024 * 1024     # 5 MB
MAX_READ_LINES = 2000
MAX_SEARCH_RESULTS = 200


def _write_enabled() -> bool:
    return os.environ.get("MCP_WRITE_ENABLED", "1").strip() not in ("0", "false", "False")


def _roots() -> list[Path]:
    env = os.environ.get("MCP_FILE_ROOT", "")
    roots = []
    for part in env.split(os.pathsep):
        if part.strip():
            roots.append(Path(part).expanduser().resolve())
    if not roots:
        roots.append(Path.cwd().resolve())
    return roots


class PathError_(Exception):
    pass


def _resolve(path: str) -> Path:
    """解析路径并确认在其一允许根目录内(符号链接展开后再比)。"""
    p = Path(path).expanduser()
    p = (Path.cwd() / p).resolve() if not p.is_absolute() else p.resolve()
    roots = _roots()
    if not any(p == r or r in p.parents for r in roots):
        allowed = ", ".join(str(r) for r in roots)
        raise PathError_(f"路径越界。允许的根目录: {allowed}")
    return p


def _hardlink_escape(p: Path) -> bool:
    """检测'硬链接逃逸':文件在根目录内,但同一 inode 另有名字在根外。

    resolve() 对硬链接无效(路径确实在根内,同一 inode 另有名字在根外)。
    对抗性验证实测:根目录内预置的硬链接可穿透 read/search/write。

    实现选择:直接拒绝 st_nlink > 1 的文件(O(1) per call)。
    为什么不做"扫描根内找同 inode 的第二名字"的精确判定:那需要全树
    遍历,search 场景会退化到 O(n²)。而根目录内合法使用硬链接的场景
    极少(常见于备份/去重工具),用环境变量 MCP_ALLOW_HARDLINKS=1
    可以关闭本检查。

    前提说明:创建硬链接需要本地文件系统权限(内核 fs.protected_hardlinks
    默认限制跨属主链接),所以现实风险集中在"根目录是共享/可写目录"的
    部署;但静态检测成本低,默认开启。
    """
    if os.environ.get("MCP_ALLOW_HARDLINKS", "").strip() in ("1", "true", "True"):
        return False
    try:
        st = p.stat()
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False  # 目录的 nlink 天然 ≥2(Unix 语义),不是硬链接逃逸
    return st.st_nlink > 1


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------

@server.tool(description="列出目录内容(最多 500 项)。返回名称/类型/大小/修改时间。")
def list_dir(path: str = ".", pattern: str = "*") -> str:
    """列目录。pattern 用 glob 语法过滤(如 *.py)。"""
    try:
        d = _resolve(path)
    except PathError_ as e:
        return f"[拒绝] {e}"
    if not d.exists():
        return f"[未找到] {d}"
    if not d.is_dir():
        return f"[错误] 不是目录: {d}"

    items: list[dict[str, Any]] = []
    try:
        for entry in sorted(d.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower())):
            if not fnmatch.fnmatch(entry.name, pattern):
                continue
            try:
                st = entry.stat()
                items.append({
                    "name": entry.name + ("/" if entry.is_dir() else ""),
                    "type": "dir" if entry.is_dir() else "file",
                    "size": st.st_size,
                    "modified": _fmt_ts(st.st_mtime),
                })
            except OSError:
                items.append({"name": entry.name, "type": "unknown", "size": None, "modified": None})
            if len(items) >= 500:
                break
    except PermissionError as e:
        return f"[权限不足] {e}"

    return json.dumps({"path": str(d), "count": len(items), "items": items},
                      ensure_ascii=False, indent=2)


@server.tool(description="读取文本文件内容(上限 1MB / 2000 行,自动识别二进制)。")
def read_file(path: str, offset: int = 1, limit: int = 0) -> str:
    """读文件。offset 为起始行号(1-based),limit=0 表示读到上限。"""
    try:
        f = _resolve(path)
    except PathError_ as e:
        return f"[拒绝] {e}"
    if _hardlink_escape(f):
        return "[拒绝] 文件存在根目录外的硬链接(可能绕过沙箱),已拦截。如确需访问设 MCP_ALLOW_HARDLINKS=1"
    if not f.exists():
        return f"[未找到] {f}"
    if f.is_dir():
        return f"[错误] 是目录不是文件: {f}(用 list_dir)"
    size = f.stat().st_size
    if size > MAX_READ_BYTES:
        return f"[拒绝] 文件 {size} 字节,超过 {MAX_READ_BYTES} 字节上限(避免灌爆上下文)"

    raw = f.read_bytes()
    if b"\x00" in raw[:8192]:
        return f"[二进制] {f.name} 含 NUL 字节,判定为二进制文件,({size} 字节)不返回内容"

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")

    lines = text.splitlines()
    start = max(1, offset) - 1
    end = len(lines) if limit <= 0 else min(len(lines), start + limit)
    end = min(end, start + MAX_READ_LINES)
    selected = lines[start:end]

    header = f"# {f} ({len(lines)} 行,显示 {start + 1}-{end})"
    return header + "\n" + "\n".join(f"{i + start + 1}\t{l}" for i, l in enumerate(selected))


@server.tool(description="写入文本文件(新建或覆盖;append=true 追加)。仅限根目录内。")
def write_file(path: str, content: str, append: bool = False) -> str:
    """写文件。设 MCP_WRITE_ENABLED=0 可整体关闭写操作。"""
    if not _write_enabled():
        return "[拒绝] 写操作已被禁用(MCP_WRITE_ENABLED=0)"
    try:
        f = _resolve(path)
    except PathError_ as e:
        return f"[拒绝] {e}"
    if _hardlink_escape(f):
        return "[拒绝] 文件存在根目录外的硬链接(可能绕过沙箱),已拦截。如确需访问设 MCP_ALLOW_HARDLINKS=1"

    data = content.encode("utf-8")
    if len(data) > MAX_WRITE_BYTES:
        return f"[拒绝] 内容 {len(data)} 字节,超过 {MAX_WRITE_BYTES} 字节上限"

    if f.exists() and f.is_dir():
        return f"[错误] 目标是目录: {f}"

    f.parent.mkdir(parents=True, exist_ok=True)
    mode = "ab" if append else "wb"
    try:
        with open(f, mode) as fp:
            fp.write(data)
    except OSError as e:
        return f"[写入失败] {e}"

    total = f.stat().st_size
    action = "追加" if append else "写入"
    return f"[成功] {action} {len(data)} 字节 → {f}(现共 {total} 字节)"


@server.tool(description="在根目录内搜索:name_glob 按文件名匹配,content_regex 按内容正则匹配。")
def search(path: str = ".", name_glob: str = "*", content_regex: str = "", max_results: int = 50) -> str:
    """搜索文件。同时指定两个条件时取交集。"""
    try:
        d = _resolve(path)
    except PathError_ as e:
        return f"[拒绝] {e}"
    if not d.is_dir():
        return f"[错误] 不是目录: {d}"

    flags = re.IGNORECASE if os.environ.get("MCP_SEARCH_CASE_INSENSITIVE") else 0
    rx = None
    if content_regex:
        try:
            rx = re.compile(content_regex, flags)
        except re.error as e:
            return f"[正则错误] {e}"

    cap = max(1, min(int(max_results), MAX_SEARCH_RESULTS))
    hits: list[dict[str, Any]] = []
    skipped_binary = 0
    skipped_escape = 0

    for root, dirs, files in os.walk(d):
        # 不跟随目录符号链接(默认行为),再显式过滤一次以防平台差异
        dirs[:] = [x for x in dirs
                   if x not in (".git", "node_modules", "__pycache__", ".venv")
                   and not (Path(root) / x).is_symlink()]
        for name in files:
            if not fnmatch.fnmatch(name, name_glob):
                continue
            fp = Path(root) / name

            # 单个文件也要 resolve 后校验 —— os.walk 不跟随目录链接,
            # 但【文件符号链接】会被直接读到。不校验就等于给根目录外的
            # 文件开了一扇窗(实测:root 内 symlink → 外部 secret 被读走)。
            try:
                real = fp.resolve()
            except OSError:
                continue
            if not any(real == r or r in real.parents for r in _roots()):
                skipped_escape += 1
                continue
            # 硬链接同样穿透 resolve —— 用 nlink 检测(实测可读走外部内容)
            if _hardlink_escape(fp):
                skipped_escape += 1
                continue

            entry: dict[str, Any] = {"path": str(fp)}
            if rx is not None:
                try:
                    if fp.stat().st_size > MAX_READ_BYTES:
                        continue
                    raw = fp.read_bytes()
                    if b"\x00" in raw[:8192]:
                        skipped_binary += 1
                        continue
                    text = raw.decode("utf-8", errors="replace")
                except OSError:
                    continue
                matches = [(i + 1, l.strip()[:200])
                           for i, l in enumerate(text.splitlines()) if rx.search(l)]
                if not matches:
                    continue
                entry["matches"] = [{"line": n, "text": t} for n, t in matches[:5]]
            hits.append(entry)
            if len(hits) >= cap:
                out = {"count": len(hits), "truncated": True, "results": hits,
                       "binary_skipped": skipped_binary, "escape_skipped": skipped_escape}
                return json.dumps(out, ensure_ascii=False, indent=2)

    out = {"count": len(hits), "truncated": False, "results": hits,
           "binary_skipped": skipped_binary, "escape_skipped": skipped_escape}
    return json.dumps(out, ensure_ascii=False, indent=2)


def main() -> None:
    server.run("stdio")


if __name__ == "__main__":
    main()
