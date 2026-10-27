# 分报告 B：AI Agent 凭证代理 / 密钥网关产品调研

> 检索时间：2026-10-26。无法从一手官网或文档确认的，标注「未证实」。

---

## 0. 结论先行

| 判断 | 说明 |
|---|---|
| **真正的「Agent 凭证代理」产品极少** | 只有 Infisical Agent Vault/Proxy、Keycard、Doppler for Agents 等少数把「agent 不持有真密钥，由代理注入或铸造短期凭证」做成了产品 |
| **95% 的 NHI 厂商不提供凭证代理** | Aembit 的 Blended Identity、P0、Oasis、Astrix、Entro、Clutch、Natoma 本质是「发现、治理与即时审批访问」 |
| **云厂商走「短期凭证铸造」路线** | AWS STS、GCP impersonation、Entra token 是 Model B 最成熟的实现，AgentCore Identity 把这条链路产品化 |
| **标准化正在形成** | IETF CB4A 草案把三类凭证代理模型、PDP/CDP 分离、DPoP 发送方约束写成规范骨架 |

---

## 1. HashiCorp Vault 及其 AI Agent 相关能力

| 能力 | 机制 | Agent 怎么拿到密钥 | 凭证类型 | 许可 | 成熟度 |
|---|---|---|---|---|---|
| **Vault Agent Injector** | K8s mutating webhook，注入 init/sidecar 容器，渲染模板或写内存盘 | 从文件或本地 sidecar 代理读取 | KV、Dynamic DB、PKI、cloud STS | BUSL-1.1 + Enterprise | 成熟 |
| **Vault Secrets Operator (VSO)** | K8s Operator，同步到原生 Secret 并提供 refresh | 读 K8s Secret | KV、DB、PKI、AWS/GCP/Azure 动态凭证 | 开源 | 成熟 |
| **Dynamic Secrets** | 按需铸造带 TTL 的数据库、云、SSH、PKI 凭证 | API 取 lease，过期自动 revoke | PostgreSQL/MySQL/Mongo、AWS STS、GCP IAM、Azure SP、PKI、SSH OTP | 开源 + Enterprise | 最成熟 |
| **Vault Radar** | 扫描代码/仓库中的硬编码密钥与泄露凭证 | 不发放凭证 | API Key、token、私钥 | Enterprise | 中等 |
| **Vault MCP Server（Beta）** | 把 Vault 读写以 MCP 工具暴露给 AI agent | 经 MCP 调 `vault_read` 等 | 取决于 token 权限 | MPL-2.0 | 较新 |
| **Agentic IAM（Enterprise）** | OAuth Resource Server；agent 在 Vault Agent Registry 注册；权限 = **人类基线 ACL ∩ agent OBO 上限 ∩ 单会话 RAR claims** 三者交集 | 用 IdP 签发的 RAR token 认证 | 全部 | Enterprise | 2026 新 |

**Agentic IAM 是 Vault 最有参考价值的部分**（[文档](https://developer.hashicorp.com/vault/ai/iam)）：三层权限交集 + 支持 IdP（如 IBM Verify）作为授权服务器签发 OAuth RAR token，实现「least-privileged, ephemeral permissions on behalf of a user」。

**Vault MCP Server 的警告**：官方文档明写「Depending on the query, the MCP server may expose certain Vault data, including Vault secrets, to MCP clients and LLMs. Do not use the MCP server with untrusted MCP clients or LLMs.」——它是**读取型**，把密钥库读权限交给 LLM，方向与本议题相反。

链接：[Agent Injector](https://developer.hashicorp.com/vault/docs/platform/k8s/injector) · [VSO](https://developer.hashicorp.com/vault/docs/platform/k8s/vso) · [MCP Server](https://developer.hashicorp.com/vault/ai/mcp-server) · [Agentic IAM](https://developer.hashicorp.com/vault/ai/iam)

---

## 2. NHI（非人类身份）安全厂商

| 厂商 | 定位 | 明确 AI Agent 方案 | 核心机制 | 能否代理/发放凭证 | 成熟度 |
|---|---|---|---|---|---|
| **Aembit** | Workload IAM | ✅ | **Blended Identity**：workload 身份与用户身份融合；按客户端访问策略实时签发短期凭证（对接云 STS、OAuth、DB） | ✅ 最接近「凭证代理 + workload identity broker」 | 商用 |
| **Natoma** | 企业 MCP 安全网关 | ✅ | MCP 网关：鉴权、审计、DLP，**凭证在网关侧持有并注入上游** | ✅ | 商用，已被 Snowflake 收购 |
| **Astrix Security** | NHI 安全平台 | ✅ | 第三方 OAuth 应用、服务账号、API key 的发现、posture、自动轮换 | ⚠️ 治理 + 轮换 | 商用，被 Cisco 收购 |
| **Entro Security** | NHI 检测响应 | ✅ | NHI 图谱、异常用途检测 | ⚠️ 发现为主 | 商用，SailPoint 已宣布收购 |
| **P0 Security** | 人类与机器的 JIT 访问 | ✅ | JIT + 审批流 + 会话录制 | ⚠️ 授权门，凭证由下游发放 | 商用 |
| **Clutch Security** | NHI 安全 | ✅ | 全量发现、生命周期管理、轮换编排 | ⚠️ 治理为主 | 商用 |
| **Oasis Security** | NHI 生命周期 | ✅ | 直连云和 IdP API 采集 token 流；JIT + 无人值守轮换 | ⚠️ 治理与轮换 | 商用 |
| **Token Security** | AI Agent / NHI 安全 | ✅ | 发现、归属、意图驱动权限最小化、Token MCP Server | ⚠️ 治理 | 商用，RSAC 2026 入围 |

**要点**：本质是 **CSPM for identities**——先「看见」agent 用了什么身份，再「收缩」权限。解决「agent 身份散落、长期存在、无人负责」，而不是「agent 该从哪拿密钥」。

---

## 3. 开发者密钥管理产品在 agent 场景下的能力

| 产品 | 开源 | 核心机制 | Agent 注入方式 | 许可 | 成熟度 |
|---|---|---|---|---|---|
| **Infisical（Agent Proxy / Agent Vault）** ⭐ | ✅ | **HTTP 凭证代理 + 短期凭证托管**。agent 环境只有 `infisical://path` 占位符，出站被 proxy 拦截替换；proxy 侧持真密钥并自动刷新 OAuth | 环境变量占位符 + egress proxy | MIT | 2025–2026 新，迭代快 |
| **Doppler for Agents** | ❌ | 面向 agent 的 secrets 交付 + 审计；scoped / read-only / expiring | `doppler run`、SDK | 付费 | 商用，成熟 |
| **CyberArk Conjur / Secrets Manager** | 部分 OSS | 企业级凭证库 + **Secretless Broker**（DB、HTTP 无凭证代理）+ JIT | Sidecar、Secretless sidecar、SDK | Apache-2.0 组件 + 商业 | 成熟，企业广泛 |
| **1Password Developer** | ❌ | Service Account + Connect Server / `op` CLI / SDK 运行时读取 | `op run`、SDK、Connect API | 订阅 | 成熟 |
| **Bitwarden Secrets Manager** | 部分 OSS | machine account + 访问令牌，`bws` CLI/SDK | `bws run`/SDK | 低价开源友好 | 中等 |
| **Phase.dev** | 部分 OSS | 端到端加密 secret 管理 | `phase run`、SDK | 开源部分 + 订阅 | 早期 |

**要点**：这一档正明显转向「AI agent 专用」。**Infisical Agent Vault** 是全场唯一把「agent 永远看不到真密钥」做成默认行为、并且开源的产品，技术路径与 IETF CB4A 的 Model A 一致。Doppler / 1Password 走「运行时注入 + 审计」，安全强度低于代理，但迁移成本几乎为零。

---

## 4. 云厂商：谁把 agent 当一等公民

| 平台 | 面向 agent 的专门能力 | 机制 | Agent 拿到什么 | 成熟度 |
|---|---|---|---|---|
| **AWS Bedrock AgentCore Identity** | ✅ | agent 以 workload identity 换 **OAuth 2.0 向下 API Key**；凭证存 AgentCore Identity 托管的 credential provider，运行时 SDK 取短期 token | 短期 OAuth token / API Key | 2025 GA |
| **AWS IAM Roles Anywhere** | 通用 | 非 AWS 环境用 X.509 换 STS 短期凭证 | STS 临时 AK/SK | 非常成熟 |
| **GCP Secret Manager + Workload Identity Federation** | 通用 | 外部 workload 用 OIDC token 换 GCP 短期凭证；SA Impersonation | 短期 OAuth token | 非常成熟 |
| **Google Cloud Agent Identity** | ✅ | 基于 **SPIFFE** 给每 agent 独立密码学身份；token 与 agent X.509 证书**密码学绑定防窃取**；用户凭证由 auth manager 加密、**在 Agent Gateway 解密** | 短期 token；原文「**the agent can never access the raw credential**」 | 2025 |
| **Google AP2** | ✅ | Verifiable Credentials 做可委托、可审计的支付授权 | 可验证凭证 | 早期 |
| **Azure Key Vault + Managed Identity** | 通用 | Managed Identity 免密钥获取 AKV 凭证 | 短期 AAD token → KV | 非常成熟 |
| **Microsoft Entra Agent ID** | ⚠️ 预览 | 为 agent 在 Entra 登记目录身份 | 短期 token | 预览（细节未证实） |

**Google Cloud Agent Identity 的三件套值得直接借鉴**：Agent Identity（身份与凭证）/ Agent Registry（目录：有哪些工具与目的地）/ Agent Gateway（执行访问策略 + 检查流量）。原文强调：「Unlike service accounts, agent identities are not shared by multiple workloads by default, can't be impersonated, and don't allow developers to generate long-lived service account keys.」

链接：[AgentCore Identity](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity.html) · [GCP Agent Identity](https://docs.cloud.google.com/iam/docs/agent-identity-overview) · [AP2](https://ap2-protocol.org/)

---

## 5. 专门的「AI Agent 凭证代理」创业公司

| 公司 | 是否真实 | 机制 | 形态 | 成熟度 |
|---|---|---|---|---|
| **Keycard** | ✅ Keycard Labs, SOC 2 Type II | **Agent 运行时授权层**：每 agent 独立 identity；用运行时 OIDC（Render/Fly 平台身份 token）替代静态 client secret；出站做 credential exchange；Agent Gateway 聚合 MCP 并对单次工具调用做策略 | SaaS + 专有云 | 早期商业化，文档完整 |
| **Infisical Agent Vault** | ✅ | 代理网关 + 短期凭证托管 | 开源 + SaaS | 新功能，迭代快 |
| **Token Security** | ✅ 但**不是凭证代理** | AI agent / NHI 发现与治理 | SaaS | 商用 |
| **Anchain.ai** | ✅ 但**不相关** | 区块链分析（反洗钱、加密犯罪追踪） | SaaS | — |
| **Vaultik** | ❓ **未证实** | 检索中未找到与 agent 凭证相关的公司 | — | 未证实 |
| **Hush Security** | ⚠️ 部分未证实 | 有 MCP 安全研究，是否提供凭证隔离产品未证实 | — | 未证实 |

链接：[Keycard 文档](https://docs.keycard.ai/) · [定价](https://www.keycard.ai/pricing)

---

## 6. 共同设计模式

| 模式 | 代表实现 | 解决什么 | 代价 |
|---|---|---|---|
| **① 短期动态凭证铸造（Model B）** | Vault Dynamic Secrets、AWS STS、GCP impersonation、AgentCore Identity | 消除长期密钥暴露窗口；泄露后 TTL 内自动失效 | 依赖目标服务支持短期 token；agent 内存仍有短暂真凭证 |
| **② 代理转发 / 网关注入（Model A）** | Infisical Agent Vault、CyberArk Secretless、Natoma、Keycard Gateway | agent **永远看不到真密钥**，可实时审计、DLP | 双跳增加延迟；代理成为单点 |
| **③ Sidecar / Injector 注入** | Vault Agent Injector、VSO、Conjur Follower | K8s 原生送凭证，无需改业务代码 | 强绑定 K8s；凭证仍在容器内可见 |
| **④ Workload Identity + mTLS（SPIFFE/SPIRE）** | Aembit、CB4A、SPIRE 生态 | 以「你是谁」而非「你知道什么」发放凭证 | 需要全链路 attestation，跨云联邦复杂 |
| **⑤ PDP / CDP 分离（NIST SP 800-207）** | CB4A | 决策组件碰不到凭证，发放组件不做决策 | 组件更多 |
| **⑥ 发送方约束令牌（DPoP，RFC 9449）** | CB4A | 令牌被窃也无法重放 | 目标服务普遍不支持 |
| **⑦ 用户委托 / on-behalf-of（RFC 8693）** | Keycard、AP2 | agent 代表用户行动时保留用户级授权与撤销粒度 | 后台访问需要长期委托授权，风险最高 |
| **⑧ Vault-less sealed secret** | Doppler、Phase、SOPS | 最低成本把密钥移出代码库与 CI 日志 | 明文仍在进程环境 |
| **⑨ 意图驱动的最小权限** | Token Security、P0、Aembit | 按实际意图动态收窄权限 | 依赖行为基线质量 |
| **⑩ 发现与轮换（CSPM for identities）** | Token、Astrix、Entro、Oasis、Clutch、Vault Radar | 先解决「有多少凭证、谁在用」 | 间接防护 |

### 行业信号：IETF CB4A

`draft-hartman-credential-broker-4-agents-00`（2026-03）把 ①②④⑤⑥ 组合成可实现的架构：agent 拿 SVID → 提交 Task Request Envelope → PDP 判决 → CDP 铸造短期、不可续期、DPoP 绑定的令牌。并给出三条「broker 绕过防护」教训：
1. agent 必须**无法直连 vault**；
2. 用**网络层**而非 agent 自觉来强制；
3. 用**目标服务审计日志**做旁路检测。

链接：https://datatracker.ietf.org/doc/html/draft-hartman-credential-broker-4-agents

---

## 7. 选型建议

| 场景 | 推荐 |
|---|---|
| 已在 K8s、已有 Vault | Vault Agent Injector + Dynamic Secrets；新 agent 场景叠加 MCP Server（但注意它是读取型） |
| 从零做 agent 凭证隔离、不想运维 Vault | **Infisical Agent Vault**（开源、Model A）或 **Keycard**（托管） |
| 全栈 AWS / Bedrock | **AgentCore Identity** |
| 全栈 GCP | **Google Cloud Agent Identity** |
| 已有 CyberArk | Conjur Secretless，或 CyberArk AI agent 治理产品线（需向售前确认能力边界） |
| 合规优先、要「agent 是谁、谁批准、做了什么」 | Aembit Blended Identity 或 P0，再叠加 NHI 发现厂商 |
| 只想先把硬编码密钥清掉 | Doppler / 1Password SA / Bitwarden SM，成本最低但隔离最弱 |
