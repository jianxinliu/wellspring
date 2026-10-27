# Agent 密钥/敏感信息管理方案调研

调研时间：2026-10-26。目标问题：**市场上有没有让 Agent 用得到密钥、但看不到密钥的方案？**

## 文档索引

| 文件 | 内容 |
|---|---|
| [AGENT-SECRETS-RESEARCH.md](./AGENT-SECRETS-RESEARCH.md) | **主报告**：全景地图、L0–L4 分级、产品矩阵、协议标准、选型建议、自研参考架构 |
| [research-runtime-isolation-report.md](./research-runtime-isolation-report.md) | 分报告 A：运行时隔离 / 沙箱 / 出口代理 / 凭证注入实现细节 |
| [research-credential-broker-report.md](./research-credential-broker-report.md) | 分报告 B：密钥管理与凭证网关产品（Vault、Infisical、Keycard、NHI 厂商、云厂商） |
| [research-mcp-report.md](./research-mcp-report.md) | 分报告 C：MCP 生态的凭证处理（网关、secrets server、三种姿势对比、CVE） |
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
