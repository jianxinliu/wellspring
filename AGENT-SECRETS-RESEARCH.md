# 给 Agent 管密钥、又不让它看见密钥 —— 市场方案全景调研

> 调研时间：2026-10-26 ｜ 口径：以官方文档、官方仓库、规范原文、CVE 库一手来源为准；无法一手核实的标注「未证实」。
> 分项证据链见同目录下 4 份子报告：运行时隔离 / 凭证网关 / MCP 生态 / 风险与标准。

---

## 0. 结论先行

### 0.1 你要的东西市场上有，但没有「一个产品全包」

「让 Agent 用得到敏感信息、但看不到敏感信息」这个需求，在 2025–2026 已经被拆成三层分别产品化：

| 层 | 解决什么 | 代表产品 | 成熟度 |
|---|---|---|---|
| **存储层** | 密钥不落盘、不进 Git、集中轮换 | HashiCorp Vault、Infisical、Doppler、1Password、AWS/GCP/Azure Secrets Manager | 非常成熟，但**不解决**「agent 运行时读得到」 |
| **代理/注入层** ⭐ | **Agent 永远看不到真值** | Infisical Agent Vault、NVIDIA OpenShell、E2B Secrets、Docker MCP Gateway、Keycard、AWS AgentCore Identity、Pipedream/Zapier MCP | 2025–2026 新出，**这才是你真正需要的那一层** |
| **治理层** | 谁有这个非人身份、该不该给、有没有人管 | Aembit、Astrix、Entro、P0、Oasis、Token Security、Natoma | 商用已有；主要做发现与收缩，只有少数站在凭证交付路径上 |

**关键判断：只上存储层 ≠ 安全。** GitGuardian 2025 年报告里有个反直觉数据：装了 secrets manager 的 2,584 个仓库，泄露率 **5.1%**，反而高于 GitHub 平均的 **4.6%**（[来源](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2025-pr/)）。因为 vault 只保证「存在保险箱里」，不保证「agent 打开保险箱时没人看」。

### 0.2 一句话判据

> **Agent 应该能「请求一个动作」，但不能「请求一把钥匙」。**

所有有效方案都在做同一件事：**把凭证的表达力从「一个字符串」换成「一个有 TTL、有 audience、有出口约束的会话」**。

### 0.3 为什么这件事必须在 2026 年做

| 数据 | 数值 | 来源 |
|---|---|---|
| 2025 年 GitHub 新增泄露密钥 | **约 2,900 万条**，YoY **+34%**，史上最大单年增幅 | [GitGuardian SoSS 2026](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026-pr/) |
| AI 服务类凭证泄露 | **1,275,105 条**，YoY **+81%** | 同上 |
| AI 辅助代码的泄露率 | 约全站基线的 **2 倍**；Claude Code 辅助 commit 约 **3.2%** | 同上 |
| MCP 配置文件暴露的唯一密钥 | **24,008 个**（其中 2,117 个仍有效） | 同上 |
| 公开 MCP 配置文件的硬编码明文率 | **12%**；其中 **55%** 无可识别 token 形态，扫描器抓不到 | [Hush Security《State of MCP Configuration》](https://www.hush.security/state-of-mcp) |
| 仍在使用静态 API key 的组织 | **约 44%** | [CSA Agentic Identity Survey 2025](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_ai_induced_lateral_movement_20260309-csa-styled.pdf) |
| 2022 年的有效泄露密钥，到 2026 年仍未吊销 | **64%** | GitGuardian SoSS 2026 |
| NHI 与人类身份比例 | 约 **82 : 1** | CSA 同上 |

---

## 1. 威胁模型：为什么「给 agent 一个 key」等于「把 key 给攻击者」

### 1.1 致命三元组（Lethal Trifecta）

Simon Willison 2025-06 提出（[原文](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)）：一个 agent 同时具备以下三项，就必然可被 prompt injection 利用外泄数据：

1. 能访问**私有数据**（代码、仓库、`.env`、数据库）
2. 暴露于**不可信内容**（issue、README、网页、依赖、MCP 工具返回）
3. 具备**对外通信能力**（curl、DNS、markdown 图片、push）

**coding agent 三项全中。** 而且「能读 `.env`」这一点让三元组退化成一次 `curl`。

### 1.2 已公开验证的攻击（全部一手 PoC）

| 研究 | 目标 | 手法 |
|---|---|---|
| [Embrace the Red](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/) | Claude Code | 利用**自动放行的命令白名单**（`ping`/`nslookup`/`dig`）把 `.env` 内容塞进 DNS 子域名带走（CVE-2025-55284） |
| [Embrace the Red](https://embracethered.com/blog/posts/2025/devin-can-leak-your-secrets/) | Devin | 内置 secrets 以**环境变量**注入运行时，经 curl 外泄 |
| [Embrace the Red](https://embracethered.com/blog/posts/2025/openhands-the-lethal-trifecta-strikes-again/) | OpenHands | markdown 图片零点击外泄 `GITHUB_TOKEN`；**模型先拒绝、再用编码绕过拒绝** |
| [Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability) | GitHub 官方 MCP | public repo 的恶意 issue 劫持 agent，把私有仓数据写进 public PR；**用 Claude 4 Opus 仍被绕** |
| [Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack) | s1ngularity/Nx 真实攻击 | 恶意 npm 包**武器化已安装的 AI CLI**（`--dangerously-skip-permissions` / `--yolo`），窃走 1000+ GitHub token、数十个云凭证；二阶段 5500+ 私有仓库被公开 |

### 1.3 一个反直觉但极其重要的架构结论

> 「**突围在 agent 拿到权限的那一刻就已经发生了。**」
> —— [CSA, AI-Induced Lateral Movement](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_ai_induced_lateral_movement_20260309-csa-styled.pdf)

推论：**防御必须建立在边界上（进程隔离、网络出口、凭证可达性），不能在提示词或模型对齐上。** 多个 PoC 已证明：写「禁止泄露密钥」的系统提示可以被绕过（OWASP LLM02 原文也承认这一点：「such restrictions may not always be honored and could be bypassed via prompt injection」）。

---

## 2. 核心框架：L0–L4 隔离强度分级

这是我的调研里最有用的一个工具。**同一档内的产品可以互换，跨档不能糊弄。**

| 档 | 名称 | 机制 | Agent 看得见什么 | 泄露后果 | 代表实现 |
|---|---|---|---|---|---|
| **L0** | 直接给 key | 明文放 `.env` / 写进 prompt / 硬编码 | **真值** | 全量、永久、不可撤回（且可能已进 LLM 上下文） | 现状的 90% |
| **L1** | 环境变量注入 | `op run` / `doppler run` / `infisical run` / `direnv` / `vault exec` / K8s Secret | **真值**（`env`、`/proc/*/environ` 可读） | 全量；可用 scoped/expiring token 缩小影响面 | 1Password CLI、Doppler for Agents、Infisical CLI |
| **L2** | 代理转发 | 网关持 key，agent 只拿虚拟 key 或占位符，出网时注入 | 虚拟 key / **占位符** | 虚拟 key 可即时吊销限额；真值不在 agent 侧 | Infisical Agent Vault、LiteLLM、Docker MCP Gateway、Envoy credential_injector、Cloudflare Worker |
| **L3** | 短期动态凭证 | 铸造分钟级凭证，或用 OAuth 换权 | 分钟级 token | 影响有界（TTL 内、scope 内） | Vault Dynamic Secrets、AWS STS、OIDC 联邦、AgentCore Identity、RFC 8693 |
| **L4** | 无凭证 mTLS + 策略 | 身份即证书，按工作负载身份授权 | **完全没有密钥** | 无「可窃取的凭证」，只有可撤销身份 | SPIFFE/SPIRE、Istio/Linkerd mTLS、Google Cloud Agent Identity |

### 2.1 三个必须记住的判据

1. **L1 不是隔离，只是「不落盘」。** 真值进了子进程 env，agent 一句 `env` 或者读 `/proc/<pid>/environ`（同 UID 无需 root）就全看到了。**如果你的 agent 就是那个子进程，L1 = L0。**
2. **L2 的强弱 100% 取决于「agent 能不能绕过代理」。** Linux 下必须 egress deny-all-except-proxy，否则 `unset HTTPS_PROXY` 一行就绕过。
3. **真正的「agent 不碰敏感信息」= L2 + L3 同时成立**：占位符/虚拟 key 解决「看得见」，短 TTL + scope 解决「偷到也没用」。

### 2.2 落地演进路径

```
L0/L1 现状
  │  ① 把真值从 agent env 里拿掉，改成虚拟 key（一天投入）
  ▼
L2 代理转发  ← 性价比最高的一跳
  │  ② 让真值有 TTL：接 STS AssumeRole / Vault 动态账号 / OAuth refresh
  ▼
L3 短期动态凭证
  │  ③ 让「没有密钥可偷」：SPIFFE SVID + mTLS，服务端按 SPIFFE ID 授权
  ▼
L4 无凭证工作负载身份
```

---

## 3. 产品全景矩阵

### 3.1 ⭐ 第一类：真正的「Agent 凭证代理」（最贴你的需求）

这类产品的共同形态：**Agent 拿着假值/占位符，请求出网时在代理侧被替换成真值，且只对白名单 host 生效。**

| 产品 | 开源 | 核心机制 | 亮点 | 链接 |
|---|---|---|---|---|
| **Infisical Agent Vault** | ✅ 单二进制 | 本机起一个 MITM 代理；agent 环境里写 `__anthropic_api_key__` 这种假值，`HTTPS_PROXY` 指向它，出网时替换 | `agent-vault run -- claude`，**对 MCP / CLI / SDK 全透明、不改代码**；service + 按 method/path 限定 + session TTL（30m/8h/7d） | [repo](https://github.com/Infisical/agent-vault) · [商业版](https://infisical.com/platform/agent-vault) |
| **NVIDIA OpenShell** | ✅ Apache-2.0 | 内核沙箱（Landlock + seccomp user-notify）+ 占位符注入 + 两把独立的锁（网络策略 × credential binding） | **实现最完整**：从 `/proc` 观察真实可执行文件而非信任 agent 自称；AWS SigV4 重签名；`openshell-prover` 形式化验证策略；supervisor 断连即冻结 agent | [docs](https://docs.nvidia.com/openshell/latest/about/overview) |
| **E2B Secrets** | ✅ Apache-2.0 | Firecracker microVM + **per-host request transform** | 未声明 host 的请求**根本不会带上凭证**（endpoint 白名单 + 凭证绑定两把锁） | [docs](https://docs.e2b.dev/secrets/inject) |
| **Docker MCP Gateway** | ✅ MIT | 每个 MCP server 一个容器；secrets 存 Docker Desktop 密钥库，**按 server 隔离**；`--block-secrets` 默认开 | 已在用 Docker Desktop 的话几乎零成本；前后扫参数与响应里的疑似 secret | [repo](https://github.com/docker/mcp-gateway) |
| **Keycard** | ❌ SaaS | Agent 运行时授权层：OIDC runtime identity（无 client secret）+ 出站 credential exchange + Agent Gateway | SDK/CLI/MCP 多形态；SOC 2 Type II | [docs](https://docs.keycard.ai) |
| **IBM ContextForge** | ✅ Apache-2.0 | MCP/A2A 联邦网关；**per-gateway + per-user OAuth token 加密落库 + 自动 refresh** | 企业级最成熟的 MCP 凭证托管开源实现 | [repo](https://github.com/IBM/mcp-context-forge) |
| **Pomerium MCP Upstream OAuth** | ✅ Apache-2.0 | 身份感知代理同时做上游 OAuth 客户端，代存代刷代销 token | per-user 而非 per-shared-secret | [docs](https://www.pomerium.com/docs/capabilities/mcp/mcp-upstream-oauth) |
| **Pipedream Connect / Zapier MCP / Metorial** | 部分 | 平台持所有 app 凭证，agent 只调语义化工具 | 3000+ 集成立等可用；不碰凭证 | [Pipedream](https://pipedream.com/docs/connect/api-proxy) · [Zapier](https://docs.zapier.com/mcp/overview/how-connections-work) |

> **首选建议**：如果目标是「Agent 接系统但不接触密钥」，先看 **Infisical Agent Vault**（开源、单二进制、不用改 agent 代码）和 **Docker MCP Gateway**（如果 MCP 是你的主集成方式）。如果 agent 会跑任意代码，看 **OpenShell / E2B Secrets**。

### 3.2 第二类：密钥管理平台（存储层，未必隔离）

| 产品 | 开源 | Agent 相关能力 | 判断 |
|---|---|---|---|
| **HashiCorp Vault** | BUSL-1.1 | Agent Injector（sidecar 注入）、VSO、**Dynamic Secrets**（按需铸造 DB/云/PKI 凭证）、Radar、**Vault MCP Server（Beta）**、**Agentic IAM（Enterprise）** | 最完整的「存储+铸造+审计」三件套；Agentic IAM 用 **RAR（Rich Authorization Requests）+ agent registry** 实现三层权限交集：人类基线 ACL ∩ agent OBO 上限 ∩ 单会话 RAR。运维重。 |
| **Infisical** | ✅ MIT | Agent Vault / Agent Proxy + CLI + SDK + PKI | 见 3.1，开源侧最贴近目标 |
| **Doppler for Agents** | ❌ | scoped / read-only / expiring token，运行时注入，agent 不可编辑 | 官方定位明确面向 agent，但属 **L1** |
| **1Password Developer** | ❌ | Service Account + `op run` + **Environments MCP Server**（只返回变量名，永不返回值，逐 Environment 人工授权）+ Credential Broker | **唯一在 MCP 层做了定向「用而不看」设计**的商业实现 |
| **CyberArk Conjur / Secretless** | 部分 OSS | **Secretless Broker**：DB / HTTP 无凭证代理，agent 代码里根本没有密码 | 企业级 L2 的标杆，老牌 |
| **Bitwarden Secrets Manager / Phase.dev** | 部分 | machine account + CLI 注入 | L1，低价/开源友好 |

**Vault MCP Server 的重要警告**：它是**读取型**的（`vault_read` / `vault_list` 能返回 secret 明文，官方文档自己写明「may expose certain Vault data, including Vault secrets, to the MCP client and LLM」）。**给 agent 挂 Vault MCP = 把密钥库的读权限交给 LLM**，在 prompt injection 场景下比单个 key 放 env 更糟。它适合「让 agent 帮你运维 Vault」，不适合本议题。

### 3.3 第三类：NHI 安全与治理（不是凭证代理）

Aembit、Astrix（已被 Cisco 收购）、Entro（SailPoint 已宣布收购）、P0 Security、Clutch、Oasis、Token Security、Natoma（已被 Snowflake 收购）。

它们解决的是 **「CSPM for identities」**：先「看见」agent 用了什么身份、权限多大、谁建的，再「收缩」。

只有两家真正站在凭证交付路径上：
- **Aembit** 的 **Blended Identity**（把 workload 身份与用户身份融合）+ 客户端访问策略实时签发短期凭证 → 最接近「workload identity broker」。
- **Natoma** 的 MCP 网关（网关侧持凭证并注入上游）。

其余主要做发现 → 轮换 → 审批，最终凭证仍由下游发放。

### 3.4 第四类：云厂商（走「短期凭证铸造」路线）

| 平台 | 面向 agent 的能力 | 判断 |
|---|---|---|
| **AWS Bedrock AgentCore Identity** | agent 用 workload identity 换短期 OAuth token / API key，凭证存 provider 侧，agent 只拿派生凭证 | **目前唯一把「agent credential provider」做成托管服务的云** |
| **AWS IAM Roles Anywhere / STS** | 非 AWS 环境用 X.509 换 STS 临时凭证 | Model B 原型，极成熟 |
| **GCP Workload Identity Federation + Secret Manager** | OIDC → 短期 GCP 凭证 | 极成熟，但未单独包装成 agent 产品 |
| **Google Cloud Agent Identity** | **每个 agent 一个 SPIFFE 身份**，默认不共享、不可冒用、**不允许生成长期 SA key**；token 与 agent 的 X.509 证书密码学绑定防窃取；用户凭证由 **Agent Gateway** 解密注入——原文「**the agent can never access the raw credential**」 | 目前设计最彻底的云方案（[文档](https://docs.cloud.google.com/iam/docs/agent-identity-overview)） |
| **Google AP2 / Agent Payments** | 用 Verifiable Credentials 做可委托、可审计的支付授权 | 早期，但方向重要 |
| **Azure Key Vault + Managed Identity** | 免密钥获取 AKV 凭证 | 极成熟；Entra 的 agent 专属身份仍在预览（未证实细节） |

### 3.5 第五类：沙箱与运行时隔离（不是密钥方案，但常被混为一谈）

Firecracker / Kata / Cloud Hypervisor / gVisor / Wasmtime / Deno permissions / Landlock+seccomp；E2B / Modal / Daytona / Fly Machines / Cloudflare Containers。

**要点**：沙箱解决的是「agent 被攻陷后能破坏多少」，**不自动解决「agent 读得到密钥」**。一个 gVisor 沙箱里 `env` 一样能打出密钥。**沙箱必须和 L2/L3 叠加才有意义。**

### 3.6 第六类：Capability token（前沿，已有产品落地）

| 机制 | 特点 | 落地情况 |
|---|---|---|
| **Macaroons**（NDSS 2014） | HMAC 链 + caveats，可追加约束做收窄 | 学术源头 |
| **Biscuit**（Eclipse，Apache-2.0） | 公钥签名 + Datalog 策略 + **离线衰减** + revocation ids（一次吊销整棵派生树） | ⭐ **OpenAI Codex CLI 已合并基于 Biscuit 的 agent identity**（PR [#17386](https://github.com/openai/codex/pull/17386) / #17387 / #17388，flag `use_agent_identity`） |
| **UCAN** | DID 为主体的可委派能力链，local-first | Storacha `w3up` 等实际产品在用 |
| **AAT**（IETF individual draft） | 面向 agent 的任务级签名凭证，编码可调用工具清单与参数约束 | 无正式标准地位，但设计思路值得抄 |

**这条对自研特别有价值**：如果你要设计自己的 agent 凭证格式，**Biscuit 的「父 agent 可以不回源派生出更窄的子 token」+「一次吊销整棵树」** 正是多 agent 派生场景需要的语义。

---

## 4. MCP 生态：Agent 接系统最主流的方式

### 4.1 规范说了什么、没说什么（这是最容易误判的地方）

MCP 2026-07-28 授权规范（[原文](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)）：

- **MUST** 用 OAuth 2.1
- **MUST** 按 RFC 8707 校验 audience（token 必须是为这个 MCP server 签的）
- **MUST NOT** 接受或转发任何其他 token（**明令禁止 token passthrough**）
- Access token **不得**出现在 query string
- ⚠️ **stdio 传输 SHOULD NOT 走授权规范，而应「retrieve credentials from the environment」**

**推论：规范层对「让 agent 用而不看密钥」没有解。** 它只规定「agent 怎么拿到访问 MCP server 的 token」；至于这个 server 用谁的上游凭证去访问 GitHub/Slack/DB，规范完全不管，而且对本地 stdio server 直接建议用环境变量。**Hush 统计的 12% 硬编码是制度性产物，不是实现者偷懒。**

### 4.2 三种凭证处理姿势

| | **A. 密钥在 MCP server 的 env** | **B. MCP server 持 OAuth token 自动刷新** | **C. 独立凭证代理 + 短期 token** ⭐ |
|---|---|---|---|
| 典型 | 本地 stdio + `GITHUB_PAT=ghp_...` | ContextForge / Pomerium / GitHub MCP 远程版 / Zapier OAuth | Infisical Agent Vault / Pipedream Proxy / Docker MCP Gateway |
| Agent 看得见 | **能**（env、配置、`ps e`、日志） | 看不到上游凭证，但 server 进程内有明文 | **什么都看不到**（只有 TTL 有限的 session token / 假占位符） |
| 凭证寿命 | 长期静态 | access token 短期，refresh token 长期 | **分钟~小时，退出即撤销** |
| 权限粒度 | 全量（PAT = 账号权限） | OAuth scope + audience | **service + method + path prefix**（可在出网前 403） |
| 审计 | 无（同一身份） | per-user | **per-session**，记 method/host/path/outcome |
| 前提 | 无 | 上游必须是 OAuth | 需要代理进程；agent 需遵守 `HTTPS_PROXY` |
| 适用 | 单人本机、可信 server、一次性实验 | 多租户 SaaS，上游有 OAuth | **生产、非 OAuth 上游（DB 密码/静态 key）、需强审计** |

**C 类在 MCP 里的天然优势**：它**不要求 MCP server 做任何改造**。Infisical Agent Vault 的定位语说得很直白——「let AI agents use existing tools like **MCP**, CLI, SDK, API with all underlying requests automatically routed through Agent Vault」。也就是说 **C 可以把任意 A 类 MCP server 原地升级成安全的**。

### 4.3 一个独立的、常被忽视的变量：工具颗粒度

> **只要工具是语义化的（`query_db(sql)`、`send_email(to, body)`），凭证就不在 agent 可达范围内；一旦工具是通用型的（`http_request(url, headers)`、`read_secret(name)`、带明文 DSN 的 `execute_sql`），凭证必然泄漏。**

**「工具颗粒度才是 MCP 凭证安全的第一变量」**——即使上了代理，一个暴露 `http_request(url, headers)` 的 server 依然能让 agent 把 session token 花在任何地方。

正面例子：
- [**DBHub**](https://github.com/bytebase/dbhub)（字节跳动 Bytebase，MIT）：只暴露 `execute_sql` / `search_objects` 两个工具；正确用法是走 Secrets Manager `--secret_arn`。
- [**awslabs/mcp**](https://github.com/awslabs/mcp)：用 AWS Profile 临时凭证 + `--secret_arn` 自己取 DB 密码，agent 只发 SQL。
- 1Password **Environments MCP Server**：官方原话「The server can only see variable and Environment names, and never returns the secrets」。

### 4.4 MCP 侧已发生的凭证类 CVE（论证「为什么必须上网关」）

| CVE | 内容 |
|---|---|
| **CVE-2026-32625**（LibreChat） | MCP server URL 的 `${VAR}` 占位符在校验时被对照 `process.env` 展开 → 任意用户建个指向攻击者域名的 server 就能让服务端把 `JWT_SECRET`、`MONGO_URI` 拼进 URL 外传 |
| **CVE-2026-44653**（LibreChat） | 仅 `VIEW` 权限用户可通过 API 拿到 `apiKey.key` 与 `oauth.client_secret` **明文**。修复建议原文：「never returning decrypted admin-managed secrets to non-owners」——**这就是「代理持凭证、UI 只回占位符」的直接论据** |
| **CVE-2025-6514**（mcp-remote，**CVSS 9.6**） | 连一个不可信 MCP server 这一步就可能 RCE——**其上所有 env 密钥随之全失** |
| **CVE-2026-54052**（n8n-mcp，**CVSS 9.6**） | 多租户 IDOR，任意 tenant 读完其他 tenant 的 API key / Bearer token |
| **CVE-2025-4143 / 4144**（Cloudflare workers-oauth-provider） | redirect_uri 校验缺失、PKCE 缺陷 |
| **CVE-2025-69196**（FastMCP） | 未正确应用 RFC 8707 `resource` 参数 |

**模式总结**：OAuth 授权相关缺陷（redirect_uri / PKCE / resource 参数）在 2025–2026 跨 Cloudflare / Cursor / FastMCP 反复出现。**自己实现认证逻辑极大概率写错；网关的价值就是把这件事收敛成「一处正确实现」。**

---

## 5. 标准与规范现状

| 标准 | 与本议题相关的内容 |
|---|---|
| **OWASP LLM06:2025 Excessive Agency** | 三个根因（过度功能/过度权限/过度自治）+ 8 条缓解。最重要的两条：**避免开放式扩展**（点名 `run a shell command`、`fetch a URL`）；**complete mediation**——原文「Implement authorization in downstream systems rather than relying on an LLM to decide if an action is allowed or not」 |
| **OWASP LLM02:2025** | 敏感信息泄露；明确承认系统提示里的限制「may not always be honored and could be bypassed via prompt injection」 |
| **OWASP Top 10 for Agentic Applications 2026** | 含 identity and privilege abuse 类别（⚠️ PDF 需授权，类别名经 CSA 转述） |
| **NIST NCCoE**《Accelerating the Adoption of Software and AI Agent Identity and Authorization》（2026-02 概念文件） | 目前最贴近的国家级文件。原文直接把问题写出来了：「**How do we establish 'least privilege' for an agent, especially when its required actions might not be fully predictable when deployed?**」；并计划采用 SPIFFE/SPIRE、OAuth 扩展、SCIM、NGAC |
| **NIST AI 100-2e2025** | Prompt Injection = **NISTAML.018**，Indirect Prompt Injection = **NISTAML.015** |
| **IETF CB4A**（draft-hartman-credential-broker-4-agents） | 把凭证代理模型写成规范骨架：**Model A 代理网关 / Model B 短期 token 铸造（推荐）/ Model C 凭证包装**；基于 SPIFFE/SPIRE + NIST 800-207 PDP/CDP 分离 + DPoP（RFC 9449）发送方约束 |
| **MCP 2026-07-28** | 见 4.1 |
| **SPIFFE/SPIRE** | 给工作负载发 X.509/JWT SVID（默认 1h）。**只回答「你是谁」，不回答「你能做什么」**——授权策略仍需另配 |
| **RFC 8693 Token Exchange** | 区分 **Delegation（B 知道 A 代表它行事）** vs **Impersonation（A 就是 B）**；`act` / `may_act` claim 表达代表链 |
| **RFC 9396 RAR** | 比 scope 更细的授权请求（Vault Agentic IAM 的核心） |
| **RFC 9449 DPoP** | 发送方约束令牌，被窃也难重放 |

---

## 6. 选型建议

### 6.1 按场景

| 场景 | 推荐 | 理由 |
|---|---|---|
| 个人 / 小团队，当天要上 | **LiteLLM 虚拟 key** + 自建出口代理（Cloudflare Worker 或 mitmproxy） | 零成本，真值只在一处，虚拟 key 可即时吊销限额 |
| 已用 Docker Desktop | **Docker MCP Gateway** | secrets 按 server 隔离，`--block-secrets` 默认开，迁移成本最低 |
| 已用 K8s + Vault | Vault **Dynamic Secrets + Agent Injector / VSO** | 复用现有栈，动态凭证天然短 TTL |
| 想要开箱即用的「agent 不碰明文」 | **Infisical Agent Vault**（开源单二进制） | 不改 agent 代码；session TTL + method/path 级规则 + 审计 |
| agent 会跑任意代码 / 高安全 | **NVIDIA OpenShell** 或 **E2B Secrets** | 内核沙箱 + 沙箱外占位符替换 + 策略形式化验证 |
| 以 MCP 为主的集成 | **ContextForge**（自托管）或 **Cloudflare MCP Portals / Keycard**（托管） | per-user OAuth 代存代刷 |
| 全栈 AWS | **Bedrock AgentCore Identity** | 唯一的 agent credential provider 托管服务 |
| 全栈 GCP / 要最强身份模型 | **Google Cloud Agent Identity** | 每 agent 独立 SPIFFE 身份 + 网关解密注入 |
| 出海合规、要审计闭环 | **Aembit / P0** + NHI 发现厂商（Token Security / Oasis） | 身份治理 + JIT |

### 6.2 按隔离目标（推荐组合）

| 目标 | 最小组合 |
|---|---|
| 「agent 不能把 key 打印出来」 | L2：任意持凭证的出口代理 + egress deny-all-except-proxy |
| 「key 泄漏了也无所谓」 | L3：动态凭证 / STS / OAuth，TTL ≤ 1h |
| 「没有任何东西可被偷」 | L4：SPIFFE SVID + mTLS，服务端按 SPIFFE ID 授权 |
| 「生产级、可审计、可撤销」 | **L2 + L3 + 每会话凭证 + 审计日志 + 高风险动作 human-in-the-loop** |

---

## 7. 如果你想自研：参考架构

如果市场上的方案都不完全贴合（例如你需要在自研 agent 框架里内建），下面是综合各家设计收敛出的骨架：

```
                    ┌──────────────── 控制面（PDP）────────────────┐
                    │  策略：哪个 agent 身份 × 哪个目标 × 哪个动作 │
                    │  显式绑定 agent 身份（SPIFFE / OIDC / mTLS） │
                    └───────────────────────┬──────────────────────┘
                                            │ 决策（不含凭证）
  Agent 进程（不可信）                       ▼
  ├─ env 里只有占位符           ┌────── 执行点（CDP / 代理）──────┐
  │  ANTHROPIC_KEY=__ph_1__    │ ① 校验调用方真实身份           │
  ├─ 只能连到本地代理           │   （读 /proc 实际 exe，不信自称）│
  │  HTTP(S)_PROXY=127.0.0.1   │ ② 校验目标在 binding 白名单内   │
  │  egress: deny all except   │   （host + port + path + method）│
  │  proxy（网络层强制）        │ ③ 解析占位符 → 取短期凭证       │
  └────────────┬───────────────┤ ④ 注入 header / 重签 SigV4      │
               │               │ ⑤ 记审计（method/host/path，    │
               │ 占位符请求     │   不记 body/header）            │
               ▼               │ ⑥ 违规 → 403 + fail-closed      │
        上游 API / DB ◄────────┴────────────────────────────────┘
               ▲
               └── 凭证源：Vault 动态凭证 / STS AssumeRole / OAuth refresh
                   （refresh token 与 client secret 永不进 agent 侧）
```

### 7.1 七个必须做对的设计点（来自各家踩过的坑）

1. **调用方身份不能靠 agent 自称**。OpenShell 的做法：从可信 `/proc` 观察真实可执行文件。
2. **两把独立的锁**，缺一即拒：① 网络策略允许「调用方 + 目标」；② credential binding 含 `host/port/path`。E2B 与 OpenShell 都是这个设计。
3. **网络层强制，不靠 agent 自觉**：egress deny-all-except-proxy。否则 `unset HTTPS_PROXY` 一行绕过。
4. **fail-closed**：代理断连 → 冻结 agent（OpenShell 的做法），而不是「降级直连」。
5. **refresh token / client secret 永不进沙箱**，只回写 access token。
6. **日志不记 body / header**，只记 method/host/path/outcome——否则日志本身成了泄露源。
7. **审计要能归因到人**：per-session、绑定人类 sponsor。CSA 数据显示只有 **28%** 的组织能做到这点。

### 7.2 不该做的

- ❌ 用提示词写「禁止泄露密钥」——可被绕过，OWASP LLM02 已明说
- ❌ 依赖「安全命令白名单」——`ping` 就能做 DNS 外泄（CVE-2025-55284）；环境变量污染能绕过 allowlist（CVE-2026-22708）
- ❌ 认为「日志里 mask 了 secret 就安全」——mask 只防日志，不防读取
- ❌ 认为「agent 防火墙是完整方案」——GitHub 官方文档自己写「should not be considered a comprehensive security solution」
- ❌ 把 MCP 配置文件当 `.env` 的替代——它**设计上就是要提交进仓库的**
- ❌ 一个共享 key 给所有 agent / 所有环境
- ❌ 在有真实凭证的机器上开 `--yolo` / `--dangerously-skip-permissions`——s1ngularity 就是这么打的
- ❌ 泄漏后只删那行代码——Hush 原文：「**Deleting the line feels like remediation and accomplishes nothing.**」必须到厂商处轮换

---

## 8. 行动清单（按投入产出排序）

**第一周**
1. 审计所有 MCP 配置 / `.env` / CI 变量里的硬编码密钥，**到厂商处轮换**（不是删行）
2. 关掉 agent 环境里的 `--yolo` 类默认开关
3. 把 LLM API key 换成 LiteLLM 虚拟 key（限额 + 可吊销 + 按 key 记账）

**第一个月**
4. 给 agent 加**出网代理 + 域名白名单**（egress deny-all-except-proxy）
5. 把 `run_shell` / `fetch_url` 这类开放式工具换成语义化动作接口
6. 引入 L2 凭证代理（Infisical Agent Vault / Docker MCP Gateway），agent env 里只留占位符

**一个季度**
7. 给每个 agent（或 agent 角色）发**独立短期身份**（SPIFFE/SPIRE 或云厂商等价物）
8. 用 RFC 8693 表达 on-behalf-of，把「agent 用你的 token」变成「agent 代表你行事」
9. 接全量审计（参考 OWASP Agent Control Standard 的 OTel + OCSF）

**战略**
10. 评估 Biscuit / UCAN 做工具级能力衰减（多 agent 派生场景）
11. 跟踪 MCP EMA（Enterprise-Managed Authorization）与 IETF CB4A 的演进

---

## 9. 可信度说明

| 等级 | 内容 |
|---|---|
| **A（一手可复核）** | GitGuardian 两期报告、Hush Security 研究、Wiz 事故分析、Embrace the Red / Invariant Labs PoC、GitHub Security Advisories API、OWASP 页面正文、MCP 规范正文、NCCoE 概念文件、NIST AI 100-2e2025、RFC 8693、SPIFFE 文档、Biscuit/UCAN 官网、Google Cloud Agent Identity、Claude Code / GitHub Copilot / OpenAI 官方文档、Codex CLI PR |
| **B（一手但需注明限制）** | OWASP Agentic Top 10 2026（PDF 需授权，类别名经 CSA 转述）；CSA 各研究注（标注为 Unofficial AI-assisted Research）；IETF AAT 草案（individual draft，无正式地位） |
| **C（未证实，勿引用）** | Vercel/Next.js 环境变量泄漏事件；Pillar Security 关于 Copilot/Cursor 泄露 OpenAI key 的原文（已 404）；「Vaultik」这家公司；「agent-secrets / secretless-agent」类独立项目；Entra Agent 专属身份的细节；EnvKey 现状 |

引用了以上 C 类内容的段落已在子报告中逐条标注，主报告已剔除。
