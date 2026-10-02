# file-manager-mcp

给 AI 助手用的沙箱文件管理器 —— 目录列表、读、写、搜索,全部锁在指定根目录内。

## 为什么做这个

让 AI 碰文件系统,几乎所有事故都来自同一个根因:**路径校验做在字符串上,而不是解析后的真实路径上**。

```
用户给: ../../../../etc/passwd          → 字符串前缀检查能过
用户给: data/link → /etc (符号链接)     → 字符串前缀检查也能过
```

这个服务在每次操作前先把路径 `resolve()`(展开符号链接、消掉 `..`),**再**做根目录前缀比对。两个逃逸向量一起堵死。

## 安全边界

| 边界 | 说明 |
|------|------|
| 根目录锁定 | `MCP_FILE_ROOT`(默认当前目录),所有操作先 resolve 再校验 |
| 符号链接 | 解析后比对 —— 根目录内的软链指向根目录外时同样被拒 |
| 读限制 | 单文件 1 MB / 2000 行;含 NUL 字节判定为二进制,不返回乱码 |
| 写限制 | 单次 5 MB;可用 `MCP_WRITE_ENABLED=0` 一键关闭全部写操作 |
| 搜索限制 | 最多 200 条结果;自动跳过 .git/node_modules/__pycache__/.venv |

## 安装

```bash
pip install -e .
```

## 配置

```json
{
  "mcpServers": {
    "files": {
      "command": "file-manager-mcp",
      "env": {
        "MCP_FILE_ROOT": "/home/me/projects",
        "MCP_WRITE_ENABLED": "1"
      }
    }
  }
}
```

多个根目录用 `:` 分隔(Linux/macOS)或 `;`(Windows)。

## 工具

### `list_dir(path=".", pattern="*")`
列目录,glob 过滤。返回名称(目录带 `/`)、类型、大小、修改时间。

### `read_file(path, offset=1, limit=0)`
文本读取,带行号。自动识别二进制(前 8KB 含 NUL 即判定),超 1 MB 直接拒绝而不是截断后假装成功。

### `write_file(path, content, append=false)`
写入。父目录不存在会自动创建。`append=true` 追加。

### `search(path=".", name_glob="*", content_regex="", max_results=50)`
双条件搜索:文件名 glob + 内容正则。同时给出时取交集。内容命中带行号和片段。

## 会拒绝什么

```
[拒绝] 路径越界。允许的根目录: /home/me/projects          # ../../etc/passwd
[拒绝] 路径越界。允许的根目录: /home/me/projects          # 指向外部的符号链接
[拒绝] 文件 5242880 字节,超过 1048576 字节上限(避免灌爆上下文)
[拒绝] 写操作已被禁用(MCP_WRITE_ENABLED=0)
[二进制] app.bin 含 NUL 字节,判定为二进制文件(2048 字节)不返回内容
```

## 测试

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
