# Wellspring 💧 — 凭证井

让 AI Agent **用**凭证而不**看见**凭证的本地分发式工具。

```
Agent ──MCP(stdio)──┐                    ┌─ CLI（人/脚本）
                    ├─ unix socket ──→ wellspringd ──┴─ Web UI（http://127.0.0.1:7777）
（只见描述符指纹）    （token 鉴权）      （唯一真相源，AES-256-GCM）
```

## 快速开始

源码运行要求 Bun 1.3.11 或更新版本。在本目录运行 `bun install` 安装依赖，再执行以下命令。编译后的三个二进制不依赖本机安装 Bun；当前构建对应本机平台。源码包注册了 `wellspring`、`wellspringd`、`wellspring-mcp` 三个命令入口，也可直接使用下面的 `bun run` 命令。

```bash
# 1. 启动守护进程（unix socket + Web UI）
bun run src/daemon/main.ts        # 或 ./wellspringd-bin
# Web UI: http://127.0.0.1:7777（admin token: ~/.wellspring/admin.token）

# 2. 存入凭证（推荐在 Web 表单录入，避免进入命令行历史；下例仅为合成演示值）
bun run src/cli/main.ts put cred:db_prod password 'p@ssw0rd'
# PII 建议通过 Web UI 的新增表单录入，字段选择 pii 与 phone 脱敏模式。

# 3. Agent 侧（MCP）：只见描述符
#    wellspring_list / wellspring_describe / wellspring_exec / wellspring_derive

# 4. 分发（CLI，凭证不经过 agent 上下文）
wellspring exec --secret DB_PASSWORD=cred:db_prod/password -- node app.js   # A1 env
wellspring exec --secret-fd CERT=cred:db_prod/password -- node app.js       # A2 fd 管道
wellspring exec --git-cred cred:github_pat/value -- git push                # GIT_ASKPASS + 一次性 token

# 声明意图：同一 purpose/target 会随本次 exec 的每一次 draw/draw_env/一次性令牌下发
wellspring exec --purpose deploy --target api.example.com \
  --secret DB_PASSWORD=cred:db_prod/password -- node app.js

# 5. 短期凭证：到期自动失效
wellspring put cred:temp_key value 'abc' --ttl 1h                           # 也支持 30m / 7d / 900（秒）
wellspring exec --secret TOKEN=cred:temp_key/value -- node app.js           # 过期后拒绝分发

# 6. 独立 Agent 身份：签发 scoped token，由宿主注入 WELLSPRING_CLIENT_TOKEN
wellspring client-issue release-agent       # 仅打印 token，不写入任何日志
# 7. 需要人工补录凭据：创建请求 → 用户在 Web 填写 → 查询状态
wellspring request github-release --purpose publish --channel A1/exec --target github.com --ttl 15m
wellspring request-status req_xxx
wellspring request-cancel req_xxx
```

守护进程被 kill 后残留的 socket 文件会在下次启动时自动回收；若该路径上已有存活守护进程，则拒绝启动并提示改用其他 `WELLSPRING_SOCK`。Web UI 端口默认 7777（`WELLSPRING_HTTP_PORT` 可改），端口被占用时自动改用随机端口而不是让守护进程退出。

## 结构

| 路径 | 说明 |
|---|---|
| src/core/store.ts | AES-256-GCM 存储（@noble/ciphers），指纹 + 脱敏 |
| src/daemon/main.ts | wellspringd：unix socket JSON-RPC、token 鉴权、限速、审计 JSONL |
| src/daemon/web.ts | Web 管理台：凭据库 / 审计流水 / 用量统计（127.0.0.1） |
| src/cli/main.ts | CLI：put/list/describe/view/resolve/policy/audit/exec/askpass |
| src/mcp/server.ts | MCP stdio server：6 工具，默认抑制执行输出，可选择精确值脱敏 |
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

## 任务中补充凭据

Agent 调用 `wellspring_request`，只填写需要什么、用途、交付通道、预期目标和等待期限。用户打开 Web 管理台的「待填写」，核对请求后在独立表单输入值，默认「仅本次任务」，也可选择保存。值直接交给守护进程，不经过聊天；Agent 调用 `wellspring_request_status` 获取状态，只有完成后才返回 `secret://…` 引用。

临时凭据随请求期限到期，后台在后续请求或读取前清理；这不是用一次即焚。等待期间 Agent 应暂停并让用户填写，不要持续轮询。请求状态持久化，守护进程重启后仍可继续。取消、过期或已经完成的请求不能再次填写；保存时目标条目已存在会报错，避免覆盖旧凭据。

MCP 示例（没有秘密值）：

```json
{"name":"wellspring_request","arguments":{"label":"GitHub 发布凭据","purpose":"publish_release","target":"github.com","channel":"A1/exec","ttlMs":900000}}
```

完成后用返回的 ref 执行 `wellspring_exec`，同时传入相同的 `purpose` 和 `target`。`wellspring_request_status` 的 `cancel:true` 可取消等待中的请求。当前不会自动唤醒 MCP 宿主里的任务；用户填写后让 Agent 继续检查状态。

ref 只在查询时才知道，所以 **Agent 必须自己保留 requestId**：`request_status` 按 id 查询，请求记录保留 7 天后清理，此后用该 id 查询会得到 `no such request`。跨任务复用的凭据应在提交时选择「保存供以后使用」并给出名称，之后从 `wellspring_list` 里找条目；「仅本次任务」的值随请求期限到期删除，过期后取不回来，只能重新发起请求。

### 每项凭据的使用范围

Web 凭据字段的「使用范围」可限制调用者、通道、用途、目标。各列表按精确字符串匹配，不同维度同时满足才放行，空的维度不限制。校验在守护进程中执行，先检查范围再解密或读取外部来源；批量环境变量先检查所有字段。轮换或切换来源保留既有范围。

调用者由宿主提供的令牌确定，不相信 Agent 参数里的身份。人类管理员身份是 `admin`，也受字段范围检查。宿主可用 `wellspring client-issue release-agent` 签发独立令牌，然后通过受保护的宿主环境 `WELLSPRING_CLIENT_TOKEN` 注入 CLI/MCP；不要把令牌放入对话。没有配置时保持读取 admin token 的兼容行为，因此按 Agent 隔离需要宿主明确配置独立令牌。相同调用者名称表示同一权限主体。

**用途和目标是调用方声明的意图，只做精确策略匹配，不核验网络流量或实际进程目的地。** 有权修改接收程序、读取同 UID 文件或操作宿主配置的 Agent 仍可能接触秘密；要获得更强隔离，应配合可信执行器和独立 OS 权限边界。

## 外部来源（值不存进来）

凭据不必存进 Wellspring。一个字段可以只记录**来源**，每次取用时现读：宿主机环境变量、某个文件、`.env` 里的某一项、钥匙串条目，或一条命令的输出。存储里只有来源地址，没有密文。

```bash
# 绑定到宿主机的 .env 里的某个变量（不需要把值敲进 shell，也就不会进 history）
wellspring put cred:db_prod password --from 'dotenv:/Users/you/app/.env#DB_PASSWORD'

# 其它来源
wellspring put cred:api value  --from env:OPENAI_API_KEY
wellspring put cred:ssh value  --from file:/Users/you/.ssh/id_ed25519
wellspring put cred:gh  value  --from keychain:github-token
wellspring put cred:dyn value  --from 'command:op read op://vault/db/password'
```

改宿主机文件即完成轮换，Wellspring 不用参与。反过来，如果想把外部值固化进加密存储（之后不再跟随宿主机），执行 `wellspring adopt <id> <field>`。

| 来源 | 写法 | 说明 |
|---|---|---|
| 环境变量 | `env:NAME` | 读守护进程自己的环境 |
| 文件 | `file:/绝对路径` | 整份文件内容，去掉末尾换行 |
| .env | `dotenv:/绝对路径#KEY` | 支持 `#` 注释、`export`、引号、行内注释 |
| 钥匙串 | `keychain:SERVICE` | macOS `security find-generic-password -s SERVICE -w` |
| 命令 | `command:<shell 命令>` | 每次取用时执行，30s 超时 |

行为约定：

- **视图不读源。** `list`/`describe` 只显示来源标签（如 `dotenv:…app.env#DB_PASSWORD`，不含完整路径、不含值），预览固定为「（外部来源，未读取）」。看一眼列表不会触发读取。
- **指纹描述来源，不描述值。** 换来源会变，宿主机轮换值不会变——这正是「值不在我们这里」的体现。
- **写入时先试读一次。** 路径或变量名写错，在 `put --from` 当场就失败，而不是等到某次取用。
- **过期检查先于读源。** 已经过期的引用不会去碰宿主机文件。
- **读不到就失败，不返回空值。** 文件被删、变量没设、命令非零退出，都会让这次取用报错并计入审计。
- 外部来源的值进不了 `<1 MiB` 以上：超过即拒绝。

MCP 侧不提供写入来源的工具——把引用指向什么，是管理员动作；agent 只能看见标签。UI 的新增表单里有一个「或来源」输入框，填了就不存值。

## 派生运算（密钥不出守护进程）

Agent 最常需要的是「用密钥算出的结果」，而不是密钥本身。`wellspring_derive` 只做计算，密钥始终留在 wellspringd：

| op | 字段内容要求 | 返回 |
|---|---|---|
| `totp` | base32 种子 | 6 位验证码 + 剩余秒数 |
| `hmac` | HMAC 密钥（`alg`: `sha256`/`sha512`） | 十六进制 MAC |
| `encrypt` | base64 编码的 32 字节 AES 密钥 | base64 密文 |
| `decrypt` | 同上 | 明文 |

```json
{"name":"wellspring_derive","arguments":{"op":"hmac","ref":"secret://cred:sign_key/key","data":"GET /v1/orders","alg":"sha256"}}
```

```bash
wellspring put cred:mfa value JBSWY3DPEHPK3PXP     # base32 种子（合成示例）
wellspring derive totp cred:mfa/value              # 输出 6 位验证码与剩余秒数

# 待签名/待加密的内容从 stdin 读取，避免进入命令行历史与进程参数
printf 'GET /v1/orders' | wellspring derive hmac cred:sign_key/key --alg sha256
printf '{"amount":1}'   | wellspring derive encrypt cred:enc_key/key   # 输出 base64 密文
wellspring derive decrypt cred:enc_key/key --blob '<base64>'           # 输出明文

# 受字段「使用范围」约束的密钥，要同时声明相同的用途与目标
wellspring derive totp cred:mfa/value --purpose deploy --target api.example.com
```

四个 op 与 `put`/`draw` 同级：需要 admin 或 scoped client token、计入限速、写入审计（op 名为 `derive_<kind>`），并在解密前检查有效期。返回的是**运算结果**，原始密钥不会出守护进程。验证码、MAC 和解密明文仍可能是敏感信息；调用这些操作即允许相应结果进入 Agent 上下文，尤其应谨慎开放 `decrypt`。

上表同时列出每个 op 对字段**内容格式**的要求：TOTP 要 base32 种子，加密要 32 字节 base64 密钥。格式不符时守护进程直接报错，而不是给出错误结果。

## 目标命令白名单

`wellspring exec` 与 `wellspring_exec` 可限制目标命令，把「agent 让工具执行什么」收敛到人工批准的集合内。策略在 Web UI「访问策略」页或 `policy.json` 的 `exec` 段：

```json
{"exec":{"enabled":true,"allow":["node app.js","git **"],"deny":["curl **"]}}
```

规则按行书写，支持引号包裹含空格的参数；`*` 匹配单个位置，`**` 只在末尾时匹配任意数量参数。**拒绝规则优先**：命中 `deny` 即拒绝，不再看 `allow`。策略在读取凭据与渲染模板之前生效，因此被拒绝的执行不会留下临时文件；策略本身读取失败时按「拒绝」处理（fail-closed）。缺少 `exec` 段或 `enabled: false` 时不做限制，兼容既有配置。

`wellspring_exec` 默认不返回子进程输出。`output: "redacted"` 返回有界输出并替换精确匹配的注入值。脱敏不能阻止编码、分段到不同流或网络外传，因此目标程序必须可信。默认超时 30 秒，可通过 `timeoutMs` 设为 100–300000 毫秒。子进程不继承 MCP 协议输入和管理员令牌环境变量；同用户文件系统权限边界仍然存在。

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

## 短期凭证（TTL）

`--ttl <duration>` 在写入时设置过期时间，支持 `900`、`30m`、`1h`、`7d`，范围 1 秒到 1 年，或直接传 `expiresAt` 毫秒时间戳。到期后 `draw` 系列操作在解密之前就拒绝，审计记为 `expired`，`list`/`describe` 会显示 `expiresAt` 与 `expired` 标记。

TTL 控制 Wellspring 的本地分发期限，不会撤销上游服务中的 API Key，也不会收回已注入运行中程序的值；目前未接入 Vault/云 STS 等动态凭证签发与撤销后端。过期条目仍留在库中，只是不再分发，轮换或删除需要单独操作。轮换（重新 `put` 同名字段）时必须显式带上 `--ttl`，否则该字段会变回永久凭证，这是为了避免轮换被当成续期捷径。

`draw_env` 采用 fail-closed 策略：任一引用过期时不返回任何环境变量，因此不会出现「部分凭证已出水」的中间状态。

## 主密钥托管

默认兼容 v1：存储目录中的主密钥文件存放无前缀的 32 字节原始主密钥，旧库无需迁移。运行 `wellspring seal` 可转成 v2：`0x02 | 16 字节 salt | 12 字节 nonce | 密文及 GCM tag`，以 scrypt（N=32768、r=8、p=1）从口令派生包装密钥，再用 AES-256-GCM 包装原主密钥；凭据与指纹不变，密钥文件保持 0600。已封装的密钥也可重新 `seal`；`wellspring unseal` 则恢复为同 UID 可直接读取的 v1。设置了 `WELLSPRING_KEY` 时拒绝这两个命令，因为此时使用的是环境中的主密钥。

口令按顺序读取：`WELLSPRING_PASSPHRASE` → `WELLSPRING_PASSPHRASE_FILE` 指定的 UTF-8 文件（去掉末尾一个换行）→ macOS 钥匙串 → 仅在 stdin 为 TTY 时隐藏输入；交互 `seal` 必须再次输入确认。先配置的来源具有优先权，口令错误不会改用后面的来源。非 TTY 无口令时立即报错并提示环境变量及钥匙串，守护进程和 MCP 不会等待终端输入。

用 `wellspring keychain store|remove|status` 管理 macOS 钥匙串中的口令（account=`wellspring`，service=`wellspring-master`）；配置后守护进程可在钥匙串已解锁且允许访问时无终端启动。非 macOS 或找不到 `security` 时报告不可用，可改用环境变量或口令文件。调用使用 `spawnSync` 的独立 argv，不经过 shell；`security add-generic-password -w` 要求把口令作为参数，因此仍有短暂的进程参数可见性，不会输出子进程错误内容或将口令写入审计。

v2 将「同 UID 只需复制主密钥和凭据文件即可解密」变为「还需取得口令」。口令文件若仍可被同 UID 读取，或钥匙串访问控制允许同 UID 进程调用 `security` 取出口令，就仍不能隔离恶意同 UID 进程；需结合钥匙串访问控制或独立 OS 用户。请妥善保管口令，丢失后无法恢复封装的主密钥。

## 构建

```bash
bun run test      # 实为 bun test --timeout 30000：部分用例要起守护进程 + MCP server，
                  # 默认 5s 超时在负载下会连累共享守护进程，导致后续用例成片 ENOENT
bun run build     # 编译三个单文件二进制
```
