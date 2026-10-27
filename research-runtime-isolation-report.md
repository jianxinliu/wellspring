# AI Agent 运行时隔离 / 沙箱 / 密钥不落地 —— 技术方案调研报告

> 调研时间：2026-10（检索口径以各项目官方文档站点抓取为准）
> 说明：**所有条目均经实际网页抓取核实**；凡未能逐页核实的内容，标记为「⚠ 未逐页核实」，请勿视为事实。

---

## 0. 结论先行（TL;DR）

「让 Agent 不接触敏感信息，又能把服务接进程序」在生产上其实只有一个**共同骨架**，所有成熟方案都是这个骨架的不同裁剪：

```
Agent 进程（不可信，只看得见假值/占位符）
   │ 只能访问本地回环 / unix socket / vsock
   ▼
可信侧中介（同机进程、sidecar 或独立容器）
   ├─ 网络策略（谁知道、能连哪个 host:port:path）
   ├─ 调用方身份（哪个可执行文件发的请求）
   └─ 凭证解析（占位符 → 真值，只对授权 endpoint 生效）
   ▼
上游服务
```

差别只在于：**边界画在哪里**（进程内 / 容器 / microVM / 内核沙箱）、**谁来做替换**（env、文件、代理、mTLS）、**真值活了多久**（永久 / 分钟级 / 请求级）。

三个已被官方公开支持、且实现最完整的参考点：

| 参考实现 | 一句话 | 链接 |
|---|---|---|
| **NVIDIA OpenShell**（Apache-2.0，v0.1.5） | 内核级隔离沙箱 + 占位符凭证注入 + 策略形式化验证，最接近「agent 不碰密钥」的完整产品化方案 | [overview](https://docs.nvidia.com/openshell/latest/about/overview) |
| **E2B Secrets**（Apache-2.0） | 云端沙箱里的 per-host request transform：占位符在出口被替换，且**未声明 host 的请求根本拿不到凭证** | [docs](https://docs.e2b.dev/secrets/inject) |
| **1Password × OpenShell**（beta） | 商业密码管理器官方落地了「沙箱内只有占位符，沙箱外 gateway 替换」 | [docs](https://developer.OnePassword.dev/environments/nvidia-openshell) |

反过来说：**`op run` / `doppler run` / `infisical run` / `direnv` 这一整类只是「注入」，不是「隔离」** —— 真值进了子进程 env，agent 一句 `env` 就读到了。它们属于本文 L1 档，只解决「密钥不写进 Git/磁盘」，不解决「agent 读不到」。

---

## 1. 沙箱执行环境

### 1.1 云端托管沙箱 / 执行平台

| 产品 | 开源 | 核心机制 | Agent 侧如何调用外部服务 | 部署形态 | 许可 | 成熟度 | 链接 |
|---|---|---|---|---|---|---|---|
| **E2B** | ✅ 核心 infra 是 | Firecracker microVM 起沙箱，SDK 创建/执行代码 | **Secrets 注入机制**：stored secret 以 per-host request transform 下发，沙箱内只有占位符，出口代理替换成真值；未声明的 host 拿不到凭证 | 托管云 + 自建（`e2b-dev/infra`） | Apache-2.0（infra 仓库 LICENSE 已核实） | 生产可用，客户含大型 SaaS | [docs.e2b.dev](https://docs.e2b.dev/secrets/inject) |
| **Modal Sandboxes** | ❌ 平台闭源（SDK 开源） | gVisor 沙箱，快照/热启动 | Sandbox 内 env 注入 + 平台侧 Secrets/Proxy；代理支持自定义域名转发 | 托管云 | 商业 SaaS | 成熟（ML 批处理起家） | [modal.com/docs](https://modal.com/docs/guide/sandbox) |
| **Daytona** | ✅（Apache-2.0） | 容器/microVM 开发环境，`daytona create` 起 workspace | git/registry/secrets 由平台侧注入 | 自建 + 云 | Apache-2.0 | 中（偏 dev-environment，非强多租户） | [daytona.io](https://www.daytona.io/docs/) |
| **Cloudflare Sandboxes / Containers** | ✅ sandbox-sdk | 基于 Cloudflare Containers（Durable Object 绑定的容器） | 通过 Worker 作为出口：secret 存 Worker Secrets，由 Worker 注入 header 再转发 | 边缘云 | SDK 开源（仓库内许可） | 2025 新出，早期 | [sandbox-sdk](https://github.com/cloudflare/sandbox-sdk) |
| **Fly.io Machines** | ❌ 平台闭源 | Firecracker microVM，秒级起停 | 静态 env / Fly secrets，无内建凭证代理 | 托管云 | 商业 | 成熟但需自建出口层 | [fly.io/docs](https://fly.io/docs/machines/) |
| **Google Cloud Run jobs** | ❌ | 容器化批任务 | Secret Manager → env / volume 挂载 | GCP | 商业 | 成熟 | [cloud.google.com](https://cloud.google.com/run/docs) |
| **Docker Sandboxes**（`docker sandbox`） | ✅ | 本地每沙箱一个容器/VM，隔离文件系统与网络 | 需自行接代理/secret 注入 | 本地开发机 | Docker 商业条款 | 2025 新出 | [docs.docker.com/ai/sandboxes](https://docs.docker.com/ai/sandboxes/) |

**要点**
- 云端沙箱的「原罪」是：**只要把真值放进容器 env，agent 就能读到**。E2B 的 per-host request transform 是目前少数把「替换点挪到沙箱外」的托管实现。
- Cloudflare Sandboxes 的正确用法不是「把 key 塞进容器」，而是「容器只调你的 Worker，Worker 持 key」——这就是 L2 代理档在边缘的形态。

### 1.2 底层隔离原语（microVM / 内核沙箱 / WASM）

| 项目 | 开源 | 核心机制 | 隔离强度 | 许可 | 成熟度 | 链接 |
|---|---|---|---|---|---|---|
| **Firecracker** | ✅ | KVM microVM，~125ms 启动，AWS Lambda/Fargate 底层 | 强（硬件虚拟化边界） | Apache-2.0 | 极成熟 | [firecracker-microvm](https://github.com/firecracker-microvm/firecracker) |
| **Kata Containers** | ✅ | 每 Pod 一个轻量 VM，OCI 兼容 | 强（VM 边界，K8s 集成好） | Apache-2.0 | 成熟 | [katacontainers.io](https://katacontainers.io/) |
| **Cloud Hypervisor** | ✅ | Rust 写的 VMM，比 Firecracker 更完整的设备模型 | 强 | Apache-2.0 / BSD-3 | 成熟（Intel 主导） | [cloud-hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor) |
| **gVisor** | ✅ | 用户态内核（runsc）拦截 syscall，不需要 KVM | 中强（应用内核攻击面小，但非硬件边界） | Apache-2.0 | 成熟（GKE Sandbox 在用） | [gvisor.dev](https://gvisor.dev/) |
| **Wasmtime / WASI** | ✅ | wasm 模块只能做 capability 授权的系统调用 | 强（默认零能力） | Apache-2.0 with LLVM exception | 成熟（但生态受限：不是所有工具链可跑） | [wasmtime](https://wasmtime.dev/) |
| **Deno permissions** | ✅ | 运行时级 `--allow-net/--allow-env/--allow-read` 白名单（默认全拒） | 中（弱于进程隔离，靠白名单而非边界） | MIT | 成熟，但**只适用于 JS/TS** | [deno permissions](https://docs.deno.com/runtime/fundamentals/security/) |
| **Landlock + seccomp** | ✅（Linux 内核） | 非 root 文件系统白名单 + syscall 过滤 | 中（与宿主共用内核） | 内核 GPL | 成熟（内核 5.13+） | [landlock.io](https://landlock.io/) |

**选型建议**
- 「agent 会跑任意 shell / 装包」→ 必须 **microVM**（Firecracker/Kata/Cloud Hypervisor）或 gVisor，容器不够。
- 「agent 只是调用工具函数」→ **WASM** 或 **Deno permission** 更轻，且天然零凭证（宿主注入 capability）。
- OpenShell 的做法值得抄：**Landlock（文件）+ seccomp user-notify（网络，拦 TCP/DNS）+ 非 root 无 capability**，把「进程」和「网络」两个平面都卡住，成本远低于 VM。

---

## 2. 网络出口代理 / egress proxy

这一档解决「agent 手上的 token 是假的或不存在的，请求由代理补齐凭证并转发」。

| 产品 | 开源 | 核心机制 | 是否支持 key 轮换 / 虚拟 key | 许可 | 成熟度 | 链接 |
|---|---|---|---|---|---|---|
| **LiteLLM Proxy** | ✅ | OpenAI 兼容网关，`model_list` 存上游 key，客户端只拿虚拟 key `sk-...` | **是**：`/key/generate` 虚拟 key、按 key/team/user 记账、`/key/{key}/regenerate` 轮换 + `grace_period`、`auto_rotate` + `rotation_interval` 定时轮换、`upperbound_key_generate_params` 封顶 | MIT（开源部分）；**Key Rotation 属 Enterprise 功能**（文档明确标注） | 很成熟（LLM 网关事实标准） | [virtual_keys](https://docs.litellm.ai/docs/proxy/virtual_keys) |
| **Envoy AI Gateway** | ✅ | 基于 Envoy 的 AI 专用网关，Upstream Auth 配置上游凭证 | 是（上游认证与客户端解耦） | Apache-2.0 | 中（新，快速迭代中） | [aigateway.envoyproxy.io](https://aigateway.envoyproxy.io/) |
| **Envoy `credential_injector`** | ✅ | 官方 HTTP filter：把自定义 header / basic auth 透传到上游，值来自 SDS secret | 是（配合 SDS 轮换） | Apache-2.0 | 成熟稳定 | [Envoy docs](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/credential_injector_filter) |
| **Portkey** | ❌（网关 SDK 部分开源） | AI Gateway，虚拟 key + guardrails + 缓存 | 是（virtual keys、provider key 池） | 商业 SaaS | 成熟 | [portkey.ai](https://portkey.ai/docs) |
| **Cloudflare AI Gateway** | ❌ | 边缘 AI 网关，支持 BYOK、缓存、限流、日志 | 是（BYOK 存 key，应用只调网关端点） | 商业 | 成熟 | [cloudflare.com](https://developers.cloudflare.com/ai-gateway/) |
| **OpenRouter** | ❌ | 托管模型聚合，一个 key 调多家 | 是（平台侧 key、credits） | 商业 | 成熟 | [openrouter.ai](https://openrouter.ai/docs) |
| **Kong AI Gateway** | ✅ / 商业 | Kong Gateway 的 AI 插件，上游 auth 插件 | 是（Kong Vault 存 key） | Apache-2.0 核心 + 商业企业版 | 成熟 | [developer.konghq.com](https://developer.konghq.com/ai-gateway/) |
| **Traefik** | ✅ | 反向代理，middleware 链（headers、forwardauth） | 有限（需自建轮换） | MIT | 成熟（通用代理，非 AI 专用） | [doc.traefik.io](https://doc.traefik.io/traefik/) |
| **Squid** | ✅ | 经典 HTTP 代理 + ACL | 否（无凭证注入） | GPL-2.0 | 极成熟（只做出口白名单，不做注入） | [squid-cache.org](http://www.squid-cache.org/) |
| **mitmproxy** | ✅ | 可编程 MITM，`addons` 里可改写请求、注入 header | 可自建（脚本里放 key） | MIT | 成熟 | [mitmproxy.org](https://mitmproxy.org/) |
| **Cloudflare Workers 作为凭证注入层** | ✅（Worker 代码开源，平台闭源） | Worker 持 key，转发到上游；agent 只拿到 Worker URL | 是（Worker Secrets / KV） | Worker 代码自定 | 成熟（边缘轻量首选） | [workers docs](https://developers.cloudflare.com/workers/configuration/secrets/) |

**E2B 的具体做法（值得抄的实现细节）**：secret 不是给沙箱 env，而是给「出口代理的 per-host request transform」；沙箱进程持有的只是一个占位符，请求发到 `api.example.com` 时由代理在**沙箱外的网络路径上**替换，而请求发到 `evil.com` 时代理**不会**替换（凭证根本不出现在那个请求里）。这就是「endpoint 白名单 + 凭证绑定」两把锁。

**风险提示**：代理转发档的强弱完全取决于「agent 能不能绕过代理」。Linux 下必须同时有 egress 网络策略（deny all except proxy）+ 代理不可被 agent 关闭；否则 `HTTPS_PROXY=... unset` 一行就绕过了。

---

## 3. 凭证注入 / credential injection 的具体实现

| 机制 | 定位 | 关键做法 | 动态性 | 成熟度 | 链接/依据 |
|---|---|---|---|---|---|
| **Envoy `credential_injector` filter** | header 注入 | filter 把 header 值从 SDS 拿到的 secret 拼进请求，支持 basic_auth / generic header / 多 header | 静态（SDS 更新即轮换） | 成熟 | [Envoy](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/credential_injector_filter) |
| **Istio** | mesh 侧 egress | egress Gateway + `AuthorizationPolicy`，或 `RequestAuthentication`；配合 `ServiceEntry` 限定出口 | 借 SDS 轮换证书 | 成熟 | [istio.io egress](https://istio.io/latest/docs/tasks/traffic-management/egress/) |
| **Linkerd** | mesh 侧 | mTLS by default，`Server`/`AuthorizationPolicy` 做 L7 授权 | — | 成熟（轻量） | [linkerd.io](https://linkerd.io/2/features/server-policy/) |
| **SPIFFE/SPIRE** | workload identity | 给每个工作负载发 X.509 SVID / JWT-SVID，身份即证书，无需共享密钥 | 短周期（默认 1h，可配置更短） | 成熟（CNCF 孵化） | [spiffe.io](https://spiffe.io/docs/latest/) |
| **OAuth 2.0 Token Exchange (RFC 8693)** | 身份换 token | 服务用「自己的身份」换「针对某下游的、scope 收窄、短 TTL 的 token」 | 极短（分/秒级） | 标准成熟，实现中等 | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) |
| **mTLS 客户端证书** | 双向认证 | 服务间用证书而非 API key；服务端按 SPIFFE ID 授权 | 证书短周期 | 成熟 | [SPIFFE spec](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md) |
| **HTTP header 注入代理** | 通用 | agent 调 `http://proxy/upstream/...`，代理加 `Authorization` | 可配轮换 | 成熟 | mitmproxy / Envoy 均可实现 |
| **OpenShell providers** | 完整实现 | 见下 | 短周期 | 0.1.5（早期但完整） | [providers](https://docs.nvidia.com/openshell/latest/how-it-works/providers/overview) |

### 3.1 重点：NVIDIA OpenShell 的凭证注入（目前最完整的公开实现）

- **密钥不落地**：启动时把每个凭证替换为**不透明占位符** `openshell:resolve:env:...` 放进 agent 环境；agent 只看到占位符，请求带占位符发出去，代理在**转发前**解析。
- **两把独立的锁**（缺一 403）：
  1. **网络策略**要允许「调用方二进制 + 请求目标」；
  2. **credential binding** 要包含请求的 `host/port/path`。
  - 不满足 → HTTP 403 + `credential_endpoint_mismatch`，fail-closed，且不记录 secret/占位符/query string。
- **支持注入的位置**：header 值、Basic auth（代理解码→解析→重编码）、query 参数、URL path 段、显式 opt-in 的请求体（`request_body_credential_rewrite: true`）、WebSocket text frame、**AWS SigV4 重签名**（`credential_signing: sigv4`，代理侧重新签名）。
- **不支持**：cookie、响应体、WS binary frame、`tls: skip` 与任何非 HTTP 隧道（「remain opaque and do not support credential rewrite」）。
- **调用方身份**：从可信 `/proc` 观察真实可执行文件，**不信任 agent 自称的路径**。
- **架构**：`sandbox`（与 agent 同侧，不可信，只转发） → `supervisor`（可信，查策略、注入凭证、解 DNS、开连接） → `gateway`（控制面，签 JWT）。工作负载**唯一允许的出口就是到 supervisor 的受保护通道**，其他 egress 全部由 outer fence 拒绝。
- **通道**：互证 HTTP/2；Docker/Podman 用 Unix socket、K8s 用 mTLS Service、MicroVM 用 vsock。
- **失败关闭**：supervisor 断连 → 冻结 agent；只有同一个 supervisor 能重连。
- **动态凭证**：`provider refresh configure --strategy` 支持 `oauth2-client-credentials` / OAuth2 refresh / Google service account JWT / `aws-sts-assume-role`；**refresh token 和 client secret 永不进沙箱**，只有 access token 回写。
- **政策变更前置验证**：`openshell-prover` 对策略做形式化验证，新增「带凭证的访问」「新 HTTP method」「云 metadata 端点」都会阻塞自动批准；也可在 CI 里单独跑。

### 3.2 其他需要知道的实现要点

- **1Password × OpenShell（beta）**：官方描述「Inside the sandbox, the agent only ever works with placeholder values. When it sends a request to a host you've approved, the gateway replaces the placeholders with the real secrets outside the sandbox」——商业密码管理器正式把「占位符 + 沙箱外 gateway」作为面向 agent 的标准形态。
- **1Password Credential Broker（public preview）**：面向 CI/CD 与其他机器工作流，发短周期访问，集成入口是 GitHub Actions / Custom workflow（OIDC）。定位是 **token broker**，不是注入器。
- **ETS（Egress Traffic Security）类方案**：没有找到单独以「ETS」为名的成熟开源项目（⚠ 未检索到独立项目页）；实务上对应的是「egress gateway + 凭证注入 + SPIFFE 身份」这一组合（Envoy/Istio + SPIRE + credential_injector 即等价物）。
- **Claude Code 的企业网络支持**（参考「客户端如何配合代理」）：支持 `HTTPS_PROXY`/`NO_PROXY`；**明确不支持 SOCKS 代理**；mTLS 用 `CLAUDE_CODE_CLIENT_CERT` / `CLAUDE_CODE_CLIENT_KEY` / `CLAUDE_CODE_CLIENT_KEY_PASSPHRASE`，CA 用 `NODE_EXTRA_CA_CERTS`。

---

## 4. 本地 / 客户端侧：运行时注入到子进程 env 或临时文件

> **这一档的统一结论：解决「密钥不落盘、不进 Git」，不解决「agent 读不到」。**
> 所有 `xxx run -- cmd` 的行为都是：把真值解密 → 放进子进程 `env`（或临时文件）→ 执行 `cmd`。**子进程及其所有子进程、以及同一用户的任何进程都能读到**（`/proc/<pid>/environ` 在 Linux 上可读）。若 `cmd` 就是 agent，则等于 L0/L1。

| 工具 | 注入机制 | 真值暴露面 | 开源/许可 | 备注 | 链接 |
|---|---|---|---|---|---|
| **1Password CLI `op run`** | 从 vault 取 secret → 注入子进程 env（或按模板生成临时文件） | 子进程 env / 临时文件 | 闭源，CLI 免费 | 有 `--env-file`、模板注入；企业版有 service account | [developer.OnePassword.com](https://developer.OnePassword.com/docs/cli/) |
| **Doppler CLI `doppler run`** | branch config → `env` 注入子进程 | 子进程 env | 闭源 | **官方明确面向 coding agent**：scoped / read-only / expiring service token，「live in the process environment for the life of the process, never in a .env or project file, and never editable by the agent」 | [doppler.com/agents](https://www.doppler.com/agents) |
| **Infisical CLI `infisical run`** | 同上（`--` 后接命令） | 子进程 env | ✅ MIT（核心） | 自建友好；配合 Infisical Agent / PKI 可做短期证书 | [infisical.com/docs](https://infisical.com/docs/cli/overview) |
| **HashiCorp Vault `vault exec`** | 用 Vault 身份换取 **动态凭证**（DB 临时账号、STS）后注入 env | 子进程 env，但**凭证本身是短 TTL 的** | ✅ BSL-1.1（Vault 1.15+，非 OSI） | ⚠ 许可从 MPL-2.0 改为 BSL-1.1，商用需注意 | [developer.hashicorp.com/vault](https://developer.hashicorp.com/vault/docs/commands) |
| **direnv + 加密** | `.envrc` 在 `cd` 时把变量载入 shell | **父 shell env（最危险）** | ✅ MIT | 配合 `sops exec-env` / `pass` 读取 | [direnv.net](https://direnv.net/) |
| **sops** | 文件级加密（KMS/age/PGP），`sops exec-env` 临时解密注入 | 临时文件 / env | ✅ MPL-2.0 | 常与 `exec-env`、`decrypt --output` 搭配 | [getsops.io](https://getsops.io/) |
| **age** | 现代加密工具（`age -d` 输出到 stdout） | 由调用方决定 | ✅ BSD-3 | 无原生「run」子命令，需 shell 拼 | [age-encryption.org](https://age-encryption.org/) |
| **git-crypt** | git filter 透明加解密仓库内文件 | 工作区明文文件 | ✅ GPL-3.0 | 只解决「仓库内文件」，不解决运行时 | [github.com/AGWA/git-crypt](https://github.com/AGWA/git-crypt) |
| **macOS Keychain / Secretive / gnome-keyring / `pass`** | 系统钥匙串存储 + CLI 查询 | 由调用方决定 | 各不同（`pass` 为 GPL-2.0） | 适合「取用」，不适合「隔离」 | [passwordstore.org](https://www.passwordstore.org/) |

**风险清单（本档必读）**
1. **进程树污染**：env 会被 `fork/exec` 继承给所有子进程；agent 起一个 shell 就能 `env` 全看。
2. **`/proc/<pid>/environ`**：同 UID 可读（Linux 上不需 root）。
3. **日志/崩溃转储/遥测**：CI 日志、panic dump、`set -x`、shell history 都可能把值打出来。
4. **临时文件**：`op run` 的模板注入、sops 的 `--output` 若落在 `/tmp` 或仓库目录，可能被 shell 插件、IDE 索引、Git 拾取。
5. **env 泄漏到模型上下文**：agent 一旦 `printenv` 或读取报错信息，密钥就进了 LLM 上下文 —— **这是「不碰敏感信息」要求最容易被违反的地方，且不可撤回**。

**如果要在这档里做到「尽量接近 L3」**：用 `doppler run` 的 **scoped/read-only/expiring** token + 让 token 绑定单个 config + 设 `expires`，并给 agent 单独 branch。这仍然只是「泄漏的影响面小」，不是「泄漏不可能」。

---

## 5. 面向 coding agent 的具体集成

| 方案 | 机制 | 对 agent 的暴露 | 适用 | 链接 |
|---|---|---|---|---|
| **GitHub Actions secrets** | 仓库/组织 secret 注入 job env；OIDC 可换云凭证 | job 内可见（含所有 step） | CI 侧，agent 通常不直接接触 | [docs.github.com](https://docs.github.com/actions/security-guides/encrypted-secrets) |
| **GitHub Actions OIDC → 云 STS** | job 用 `id-token` 换短期云凭证，无需长期 secret | 短 TTL，scope 可窄 | **推荐替代长期 AK/SK** | [OIDC docs](https://docs.github.com/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect) |
| **Docker secrets**（Swarm） | secret 以文件挂载到 `/run/secrets/*` | 容器内可读文件 | 容器编排，弱于代理档 | [docs.docker.com](https://docs.docker.com/engine/swarm/secrets/) |
| **K8s Secrets** | env / volume 挂载，base64（**非加密**，只编码） | Pod 内可读 | 基础能力，需配合 RBAC/encryption at rest | [k8s.io](https://kubernetes.io/docs/concepts/configuration/secret/) |
| **External Secrets Operator** | 从 Vault/AWS SM/GCP SM 同步到 K8s Secret | 同上 | 解决「多源同步」，不解决「不落地」 | [external-secrets.io](https://external-secrets.io/) |
| **Secrets Store CSI Driver** | 把 secret 以 tmpfs 文件挂进 Pod，不写入 etcd | Pod 内可读文件 | 比 K8s Secret 好（不落 etcd） | [secrets-store-csi-driver](https://github.com/kubernetes-sigs/secrets-store-csi-driver) |
| **SPIRE on K8s** | Pod 拿 SVID，调上游时用 mTLS / JWT-SVID | **无长期密钥** | L4 落地首选 | [spiffe.io](https://spiffe.io/docs/latest/) |
| **`agent-secrets` / `secretless agent` 类项目** | — | — | ⚠ 未检索到有实质影响力的独立开源项目；语义上最接近的是 NVIDIA OpenShell、E2B Secrets、1Password × OpenShell、Doppler for Agents 这四个 | — |

**「agent 专用」现状小结**：这个赛道在 2025–2026 已经收敛出四个真实产品形态：
1. **NVIDIA OpenShell**（开源，最完整，沙箱+代理+策略+形式化验证）；
2. **E2B Secrets**（托管沙箱 + per-host request transform）；
3. **Doppler for Agents**（只做「scoped/read-only/expiring + 进程 env 注入」，明确定位 L1）；
4. **1Password**（Credential Broker = token broker 给 CI；Environments × OpenShell = 占位符 + 沙箱外注入）。

---

## 6. 按隔离强度排序的方案档次（L0–L4）

| 档位 | 名称 | 机制 | agent 能看到什么 | 泄漏后的影响 | 适用场景 |
|---|---|---|---|---|---|
| **L0** | 直接给 key | 明文 key 放 `.env` / 直接写进 prompt / 硬编码 | **真值** | 全量、永久、不可撤回（且可能已进 LLM 上下文） | ❌ 仅限一次性本地试验；生产禁用 |
| **L1** | env 注入（含本地 CLI 档） | `op run` / `doppler run` / `infisical run` / `direnv` / `vault exec` / K8s Secret → env | **真值**（`env`/`/proc/*/environ` 可读） | 全量，但可用 scoped/expiring token 缩小到「单个 config + 很短 TTL」 | ✅ 个人开发机、CI 单步；agent 可信、只跑自己写的脚本 |
| **L2** | 代理转发 | LiteLLM / Envoy AI Gateway / Cloudflare Worker / mitmproxy 持 key，agent 只拿虚拟 key 或代理 URL | 虚拟 key 或**占位符** | 虚拟 key 可即时吊销/限额；真值不在 agent 侧 | ✅ **绝大多数「agent 调 API」场景的主力档**；需保证 agent 绕不过代理 |
| **L3** | 短期动态凭证 | OpenShell provider refresh（OAuth2 CC / AWS STS AssumeRole）、Vault 动态凭证、RFC 8693 token exchange、GitHub Actions OIDC | 分钟级 access token 或占位符 | 影响有界（TTL 内、scope 内），可审计 | ✅ 云资源操作、SaaS 集成、需要「谁做了什么」可追溯时 |
| **L4** | 无凭证 mTLS + 策略 | SPIFFE/SPIRE SVID、Istio/Linkerd mTLS、OpenShell 的 supervisor↔sandbox mTLS | **完全没有密钥**（身份即证书） | 无「可窃取的凭证」，只有可撤销的身份 | ✅ 服务间调用、多租户平台、合规要求「无静态密钥」 |

### 6.1 分档落地建议

- **L1 → L2 是性价比最高的一跳**：把 `ANTHROPIC_API_KEY` 从 agent env 里拿掉，换成 LiteLLM 虚拟 key，投入一天，收益最大（可以按 agent/team 限额、吊销、审计）。
- **L2 → L3 的关键**是「真值有 TTL」：OpenShell 的 `provider refresh configure --strategy aws-sts-assume-role` 或 Vault 动态 DB 账号，把「永久 AK」换成「15 分钟凭证」。
- **L3 → L4 的关键**是「不再有密钥可以偷」：SPIFFE SVID + mTLS，agent 侧持证书（短周期自动轮换），服务端按 SPIFFE ID 授权。
- **真正的「agent 不碰敏感信息」要求 L2 + L3 同时成立**：占位符/虚拟 key 解决「看得见」，短 TTL + scope 解决「偷到了也没用」。

### 6.2 组合推荐（按团队规模）

| 团队形态 | 推荐组合 | 理由 |
|---|---|---|
| 个人开发者 / 小团队 | **L2**：LiteLLM Proxy（虚拟 key）+ Cloudflare Worker 或本地 mitmproxy 做通用 API 注入 | 零成本、当天可上；真值只在一处 |
| 中型研发（自建） | **L2 + L3**：Envoy `credential_injector` / Istio egress + Vault 动态凭证 + K8s Secrets Store CSI | 复用已有 mesh 和 Vault，无需新平台 |
| 多租户 / 高风险 agent 平台 | **L3 + L4**：NVIDIA OpenShell（或 E2B Secrets）+ SPIRE + 形式化策略验证 | 内核边界 + 占位符 + 无长期密钥 + 策略可审计 |
| CI / 自动化流水线 | **L3**：GitHub Actions OIDC → 云 STS；1Password Credential Broker | 不落长期 secret，天然按 job 生命周期 |

---

## 7. 未核实 / 存疑事项（请勿当作事实使用）

| 条目 | 状态 |
|---|---|
| Daytona、Modal、Fly.io、Cloud Run 的「凭证代理」细节 | ⚠ 未逐页核实；表中描述按公开文档的通用能力概括，具体 secret 注入语义需二次核对 |
| Cloudflare Sandboxes 的具体 secret 注入 API | ⚠ 未逐页核实；sandbox-sdk 仓库已核实存在，用法需查 README |
| 「ETS（Egress Traffic Security）」独立项目 | ⚠ 未检索到；按概念归入「egress gateway + 注入」组合 |
| `agent-secrets` / `secretless-agent` 具体开源项目 | ⚠ 未检索到有影响力的项目 |
| Vault 当前许可（BSL-1.1 vs 后续变更） | ⚠ 需按所用法版本核对；表内按 1.15+ BSL-1.1 记录 |
| LiteLLM 的 MIT 范围与 Enterprise 功能边界 | ✅ 已核实：Key Rotation 明确标注为 Enterprise 功能；其余开源部分 MIT |
| Envoy AI Gateway「Upstream Authentication」页面内容 | ⚠ 页面重定向未成功抓取，表中按产品定位概括 |

---

## 附：核心链接汇总

**沙箱**：[E2B Secrets](https://docs.e2b.dev/secrets/inject) · [E2B infra](https://github.com/e2b-dev/infra) · [Modal Sandboxes](https://modal.com/docs/guide/sandbox) · [Daytona](https://www.daytona.io/docs/) · [Cloudflare sandbox-sdk](https://github.com/cloudflare/sandbox-sdk) · [Fly Machines](https://fly.io/docs/machines/) · [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) · [Firecracker](https://github.com/firecracker-microvm/firecracker) · [Kata](https://katacontainers.io/) · [Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor) · [gVisor](https://gvisor.dev/) · [Wasmtime](https://wasmtime.dev/) · [Deno permissions](https://docs.deno.com/runtime/fundamentals/security/)

**代理**：[LiteLLM virtual keys](https://docs.litellm.ai/docs/proxy/virtual_keys) · [Envoy AI Gateway](https://aigateway.envoyproxy.io/) · [Envoy credential_injector](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/credential_injector_filter) · [Istio egress](https://istio.io/latest/docs/tasks/traffic-management/egress/) · [Linkerd](https://linkerd.io/2/features/server-policy/) · [Kong AI Gateway](https://developer.konghq.com/ai-gateway/) · [Cloudflare AI Gateway](https://developers.cloudflare.com/ai-gateway/) · [Traefik](https://doc.traefik.io/traefik/) · [mitmproxy](https://mitmproxy.org/) · [Squid](http://www.squid-cache.org/)

**身份/注入**：[SPIFFE](https://spiffe.io/docs/latest/) · [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) · [NVIDIA OpenShell](https://docs.nvidia.com/openshell/latest/about/overview) · [OpenShell providers](https://docs.nvidia.com/openshell/latest/how-it-works/providers/overview) · [1Password × OpenShell](https://developer.OnePassword.dev/environments/nvidia-openshell) · [1Password Credential Broker](https://developer.OnePassword.dev/brokered-access)

**本地/CI**：[1Password CLI](https://developer.OnePassword.com/docs/cli/) · [Doppler for Agents](https://www.doppler.com/agents) · [Infisical CLI](https://infisical.com/docs/cli/overview) · [Vault commands](https://developer.hashicorp.com/vault/docs/commands) · [direnv](https://direnv.net/) · [sops](https://getsops.io/) · [age](https://age-encryption.org/) · [git-crypt](https://github.com/AGWA/git-crypt) · [GitHub OIDC](https://docs.github.com/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect) · [Secrets Store CSI](https://github.com/kubernetes-sigs/secrets-store-csi-driver) · [External Secrets](https://external-secrets.io/)
