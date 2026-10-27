# Wellspring 💧 — 凭证井

让 AI Agent **用**凭证而不**看见**凭证的本地分发式工具。

```
Agent ──MCP(stdio)──┐                    ┌─ CLI（人/脚本）
                    ├─ unix socket ──→ wellspringd ──┴─ Web UI（http://127.0.0.1:7777）
（只见描述符指纹）    （token 鉴权）      （唯一真相源，AES-256-GCM）
```

## 快速开始

```bash
# 1. 启动守护进程（unix socket + Web UI）
bun run src/daemon/main.ts        # 或 ./wellspringd-bin
# Web UI: http://127.0.0.1:7777（admin token: ~/.wellspring/admin.token）

# 2. 存入凭证（推荐在 Web 表单录入，避免进入命令行历史；下例仅为合成演示值）
bun run src/cli/main.ts put cred:db_prod password 'p@ssw0rd'
bun run src/cli/main.ts put person:zhang_san phone '13800005678' --cls pii --mask phone

# 3. Agent 侧（MCP）：只见描述符
#    wellspring_list / wellspring_describe / wellspring_exec

# 4. 分发（CLI，凭证不经过 agent 上下文）
wellspring exec --secret DB_PASSWORD=cred:db_prod/password -- node app.js   # A1 env
wellspring exec --secret-fd CERT=cred:db_prod/password -- node app.js       # A2 fd 管道
wellspring exec --git-cred cred:github_pat/value -- git push                # GIT_ASKPASS + 一次性 token
```

## 结构

| 路径 | 说明 |
|---|---|
| src/core/store.ts | AES-256-GCM 存储（@noble/ciphers），指纹 + 脱敏 |
| src/daemon/main.ts | wellspringd：unix socket JSON-RPC、token 鉴权、限速、审计 JSONL |
| src/daemon/web.ts | Web 管理台：凭据库 / 审计流水 / 用量统计（127.0.0.1） |
| src/cli/main.ts | CLI：put/list/describe/view/resolve/policy/audit/exec/askpass |
| src/mcp/server.ts | MCP stdio server：3 工具，默认抑制执行输出，可选择精确值脱敏 |
| test/e2e.test.ts | 端到端回归测试（bun test） |

## 安全模型

- **描述符隔离**：agent 只见 `sha256` 前 16 位指纹 + 脱敏预览（`****` / `138****5678`）。
- **socket 鉴权**：敏感操作需要 admin token。0600 文件隔离其他用户，不隔离同 UID 进程；同 UID 进程仍可能读取令牌和主密钥。需要更强边界时应分离 OS 用户或容器。
- **一次性 token**：`exec --git-cred` 签发 60 秒能力令牌，限定具体凭据字段、`draw` 操作和 helper 通道；首次尝试即消耗，包括越权失败。不可批量读取、管理凭据或签发新令牌。Git 与 SSH askpass 当前共用 `git/askpass` 通道标识。
- **PII 三档**：view（脱敏）→ resolve（reason 白名单 + 限速 10/min + 橙色事件）→ deliver。
- **边界**：明文要进的程序若 agent 可控可改，终能读到——本工具的承诺是把「长期存在」变成「可见、可审计、可撤销的一次握手」。

## MCP 接入

在支持 stdio MCP 的客户端中添加（路径改为实际绝对路径）：

```json
{"mcpServers":{"wellspring":{"command":"/absolute/path/wellspring/wellspring-mcp-bin","args":[]}}}
```

先运行守护进程，再启动客户端。默认读取 `~/.wellspring/admin.token`，无需把令牌放进 MCP 配置。自定义存储位置时，在守护进程和 MCP 的环境中设置相同的 `WELLSPRING_HOME`；也可显式设置 `WELLSPRING_SOCK`。

`wellspring_exec` 需要 `command` 参数数组，可搭配 `env`、`fd`、`files` 引用映射。`env` 注入变量值；`fd` 通过 `WELLSPRING_FD_<名称>` 告知子进程只读凭据管道的描述符；`files` 注入 0600 临时文件路径并在执行后清理。还可用 `templates` 把模板文本渲染为临时配置文件。所有交付映射中的名称不可重复。

默认 `output: "none"` 只返回执行状态；`output: "redacted"` 返回有界输出并替换精确匹配的注入值。脱敏不能阻止编码、分段到不同流或网络外传，因此目标程序必须可信。默认超时 30 秒，可通过 `timeoutMs` 设为 100–300000 毫秒。子进程不继承 MCP 协议输入和管理员令牌环境变量；同用户文件系统权限边界仍然存在。

## 配置模板

模板只包含普通文本与凭据占位符，不执行表达式。`raw` 原样插入（默认）；`json` 生成带引号的 JSON 字符串，应放在 JSON 值位置；`uri` 编码为 URL 参数片段。模板本身可以进入版本库，渲染结果只写入执行期 0600 临时文件。

例如模板 `db.template.json` 的内容：

```json
{"password": {{secret://cred:db_prod/password | json}}}
```

CLI 用 `wellspring exec --template-file APP_CONFIG=db.template.json -- node app.js`，目标程序通过 `APP_CONFIG` 取得文件路径。MCP 则传入模板文本：

```json
{"name":"wellspring_exec","arguments":{"templates":{"APP_CONFIG":"{\"password\": {{secret://cred:db_prod/password | json}}}"},"command":["node","app.js"]}}
```

单个模板上限 1 MiB、256 个占位符，渲染结果上限 4 MiB。同一模板内的重复引用只读取一次。非法占位符在取用凭据前拒绝；执行结束、启动失败和普通信号退出时清理文件。SIGKILL 或进程崩溃无法执行清理，临时配置不得用于不可信程序。

## 构建

```bash
bun test
bun build --compile src/daemon/main.ts --outfile ./wellspringd-bin
bun build --compile src/cli/main.ts --outfile ./wellspring-bin
bun build --compile src/mcp/server.ts --outfile ./wellspring-mcp-bin
```
