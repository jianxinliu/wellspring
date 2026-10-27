# 凭证水管（Credential Waterworks）—— 设计文档

> 需求来源（用户原话，m00175）：
> 「代理转发太重了吧，而且侵入性太强…我要的是 agent 能方便地获取数据，但不接触任何凭证，agent 只是知道如何将保存的凭证对接到具体的程序中。就像是，凭证就是水，我们这个工具是水管，agent 只是根据谁需要什么样的水，操控水管流什么样的水，并对接到不同的目标去。这就要求，我们能够做好凭证的保存和保护，能让 agent 查询凭证，并且我们要有足够广泛的对接方式，例如，环境变量，管道……其他你调研补充。我的设想是以 mcp 的形式提供，然后有一个给人看的界面，可以进行凭证管理，审计，统计。」

---

## 0. 先校准需求：你要的不是代理，是分发器

上一轮报告里的「代理转发（L2）」是**拦截式**：它在网络路径上守着，必须改 agent 的网络配置（`HTTPS_PROXY`），要装 CA 证书做 MITM，属于「部署在中间」。你说它「太重、侵入性强」，这个判断是对的——因为那是**为了应付「不能改 agent 代码」的旧系统**而设计的架构。

你要的是**分发式**：

| | 拦截式代理（你拒绝的） | 分发式水管（你要的） |
|---|---|---|
| 部署位置 | 网络路径上，强制接管出网 | 成为一个被调用的服务，不改网络 |
| Agent 侧改动 | 改 `HTTPS_PROXY`、装 CA 证书、信任 MITM | 只多一个工具调用，或一行环境变量 |
| Agent 知道什么 | 不知道有秘密，但**网络被劫持** | 知道「有个叫 xxx 的凭证」，**拿不到真值** |
| 适用 | 已有黑盒 CLI/IDE 插件无法改 | 自己可控的项目、自研 agent |
| 心智模型 | 关卡 | **水管 / 水龙头** |

你的类比非常准确，而且它恰好对应一个已经存在的成熟范式：**Secretless（无凭证访问）/ Credential Broker**。核心差别只有一句话：

> **Agent 拿到的是「凭证描述符（descriptor）」，不是凭证本身。描述符能查、能引用、能对接，但不能反解出明文。**

**但这带来一个必须正视的矛盾**，也是整个设计的难点：

> ⚠️ **如果最终要把明文放进某个程序的 env / 文件 / 管道，而那个程序又是 Agent 能控制或读取的，那么 Agent 迟早能读到明文。**

所以本设计的目标不是「消除这个矛盾」，而是**把矛盾的窗口压到最小、并让每次泄漏都留下痕迹**：

1. **不落盘**：真值只走内存 → 进程内存 / 匿名管道 / 一次性 fd，绝不写临时文件；
2. **不落 agent 上下文**：MCP 工具**永远不返回明文**，返回的是 `env` / 指针 / 一次性 token；
3. **最短寿命**：注入即用即焚，进程退出即失效；**每一次取用都是一个有 ID 的「出水事件」**；
4. **可归因**：谁（哪个 agent session / 哪个人 sponsor）在什么时候、把哪个凭证、送到了哪个进程/文件，全量可审计。

---

## 1. 交付通道矩阵（你问的「要足够广泛的对接方式」）

这是整个产品的核心价值点。以下按**泄漏面**从小到大排序，**推荐序即从上到下**。

### 1.1 ⭐ A 类：真值不进入 Agent 可读范围（首选）

| # | 通道 | 机制 | Agent 看到 | 真值最终在哪 | 防的东西 | 适用 |
|---|---|---|---|---|---|---|
| **A1** | **包装执行（exec wrapper）** ⭐⭐⭐ | `wellspring exec --secret db_prod=DB_PASSWORD -- node app.js`；工具 fork 子进程，**在 fork 后、exec 前的窗口内**把真值写进子进程 env / fd，然后 exec | 只有命令模板，没有值 | 目标进程 env（**永不经过 agent 的 shell**） | agent 的 shell、`ps e`、日志、上下文 | 启动带凭证的程序 |
| **A2** | **一次性传参 FD** ⭐⭐⭐ | `wellspring exec --secret-file tgz=fd:3`；通过 `ExtraFiles`（Go）/ `pass_fds`（Python）传一个**只读管道**，目标程序从 fd 3 读，读完 EOF | 只有 `fd:3` | 管道缓冲区（内核态，用完即释放） | 磁盘、跨进程枚举、`/proc/<pid>/environ` | 证书、PEM、JSON、多行结构 |
| **A3** | **短命/临时凭证托管执行** ⭐⭐ | 工具先向上游换一个**只够这次任务用**的凭证（AWS STS / DB 短期账号 / OAuth），再按 A1/A2 交付；任务结束自动 revoke | 只说「要 db_read」 | 短命 token | 泄漏后长期有效 | 生产环境 |
| **A4** | **本地 TLS 终结 + 协议代理（仅调试）**（L2） | 传统代理 | 不知道 | 目标服务 | — | ≥个黑盒工具无法改时兜底 |

### 1.2 B 类：真值可被 agent 读到，但生命周期极短（可接受）

| # | 通道 | 机制 | 为什么可接受 | 限制 |
|---|---|---|---|---|
| **B1** | **一次性环境变量（per-invocation）** | `wellspring env --exec .env.rendered`：**生成内存态 env 文件后即刻 exec，文件用 `O_TMPFILE` 匿名 inode，或直接 `Environ` 传入不再存在 disk** | 没有磁盘副本；进程结束即失效 | 进程内仍可 `env` |
| **B2** | **`env` 注入 + 进程树监控** | 注入后监控该进程树的异常子进程/出站 | 有审计弥补 | 同上 |
| **B3** | **命名管道 / FIFO / unix socket**（你说到的「管道」） | `wellspring pipe db_read` 创建 unix socket 或 FIFO，任何能读它的本地程序可以按需拉取**一次** | 真值只在管道一次，读后 fd 关闭 | 无鉴权，本机同用户可抢读；需配 `SO_PEERCRED` 校验 |
| **B4** | **临时 token 交换** | 发一个 5 分钟、单次使用、绑定调用方身份的换权 token，agent 拿它去换真值 | 泄漏的是一次性擦屁股纸 | 多一跳 |

### 1.3 C 类：真值必须完整到达外部（不可避免）

| # | 通道 | 机制 | 必须配的控制 |
|---|---|---|---|
| **C1** | **模板渲染到文件** | `wellspring render --template kubeconfig.tpl --out ~/.kube/config`，文件 `0600`，可选 **`memfd` + `/proc/self/fd`** 免落盘 | 目标路径白名单；渲染后自动设置 mtime 有效期；进程退出删除；**禁止输出到项目目录**（防 git 提交） |
| **C2** | **模板渲染到 stdout / stdin** | `wellspring render --template a.tpl --stdout` | stdout 会被 agent 读到，**默认关闭，需显式 `--allow-plaintext-output`**（会记一条高危审计） |
| **C3** | **`.gitignore` / 提交前扫描联动** | 渲染前检查目标路径是否在 git 跟踪范围内 | 防泄漏到仓库 |

### 1.4 D 类：非进程交付（企业对接形态）

| # | 通道 | 用途 |
|---|---|---|
| **D1** | **MCP 工具返回指针而非值** | Agent 拿到 `secret://db_prod/password`（一个 URI），它只能把这个 URI 交给**支持解析它的工具**（`wellspring exec` 或 A2） |
| **D2** | **Secret URI 引用**（可类比 `op://vault/item/field`、`vault://path#field`、`ref+sops://`、K8s `env.valueFrom`） | 配置文件里写 URI，由工具在交付前解析——**agent 读配置文件只看到 URI** |
| **D3** | **K8s Secret / CSI 驱动** | K8s 场景原生对接 |
| **D4** | **CI OIDC 联邦** | `wellspring run -- oidc-exchange` 用 CI 的 OIDC token 换短期云凭证（不存任何长期 key） |
| **D5** | **HTTP 拉取 API（受控）** | 仅需要 `Bearer` 的场景，见 §2.3 |

### 1.5 对你这个需求的直接建议

**核心只做三件事就够覆盖 90% 场景**：

```
A1  wellspring exec   ← 主入口，覆盖「启动一个需要凭证的程序」
A2  fd 传参    ← 覆盖「证书/JSON/多行结构」
D2  secret URI ← 覆盖「配置文件里引用」，让你能 grep 到但没有明文
```

**B3 管道**保留，但默认落在「本地 socket + SO_PEERCRED 校验 + 单次读取」形态，并且**在 UI 上标黄**（因为它本质上是「谁都能来抢一口水」）。

---

## 2. 核心机制：Agent 只见描述符，不见明文

### 2.1 三个对象

```
Credential（凭证）     —— 真正的秘密。加密存储，永不离开工具的进程。
  ├─ name: "db_prod"
  ├─ type: password | api_key | pem | json
  ├─ value: [AES-256-GCM 密文]
  └─ policy: 谁能用、怎么用、多久

Descriptor（描述符）★  —— Agent 能看到的所有东西。它是公开的。
  ├─ ref: "secret://db_prod/password"
  ├─ type: password
  ├─ fingerprint: "sha256:9f2a…"        ← 用来「核对是不是同一把」，不可反解
  ├─ usable_as: ["env:PGPASSWORD", "fd:credentials.json"]
  └─ requirements: ["needs_exec", "ttl<=1h"]

DrawEvent（出水事件）—— 每次交付一条审计记录。
  ├─ event_id, agent_session, sponsor
  ├─ credential_ref, delivery_channel
  ├─ target: {cmd: "node app.js", pid: 12345}
  └─ result: success | denied | error
```

**关键设计**：描述符里的 `fingerprint` 是**单向**的（`SHA-256(value)` 的前 16 位）。它的作用是让 Agent 能在「只知道有个叫 db_prod 的东西」的前提下做判断——比如发现指纹变了、「凭证轮换了，重试」，**而永远不会因为拿到指纹就推出明文**。

这和 1Password 的 `op://` URI 引用、Kubernetes 的 `secretKeyRef` 是同一个思想：**引用可以到处传，值只能在一处。**

### 2.2 一次完整流程

```
1. Agent 开会话 → wellspring MCP `session_open(project="myapp")`
   ← 返回 session_id + 可用凭证清单（★ 只有描述符，没有值）

2. Agent 想知道怎么用 → `secret_describe("secret://db_prod/password")`
   ← 返回 type/fingerprint/usable_as/requirements
   ★ 到这里为止，Agent 全程没碰过明文

3. Agent 决定交付 → `secret_inject(...)` 或 `wellspring exec ...`
   ← 工具在**它自己的进程内**解密，直接写进目标进程

4. 记录 DrawEvent（含 cmd、pid、通道、结果）
```

### 2.3 关于 D5「HTTP 拉取」的取舍

很多产品（Infisical、Doppler）会提供一个 `GET /secrets/:path` 的 API。**我不建议把它作为核心**，因为它会让「真值进入 agent 上下文」变成一条低摩擦路径——一旦有了这条路，前面所有防线都形同虚设。

**妥协做法**：默认关闭，开启后强制要求：
- 只能由**非 agent 身份**调用（例如由 `wellspring exec` 内部调用，或由 CI 的 OIDC 身份调用）；
- **每一次调用都在 UI 上以红色「明文出水」事件展示**，并计入周报。

### 2.4 MCP 工具集（建议 7 个，克制）

| 工具 | 返回明文？ | 说明 |
|---|---|---|
| `cred_session_open` | ❌ | 开会话，返回 session_id + 可用凭证描述符列表 |
| `cred_list` | ❌ | 列出描述符（可按 tag / target 过滤） |
| `cred_describe` | ❌ | 单个凭证的详细描述符 + **使用示例**（`usable_as` 里的配方） |
| `cred_inject_exec` ⭐ | ❌ | **核心**：`{ref, env:[...], files:[...], cmd, args}` → 执行并交付 |
| `cred_render` | ⚠️ 值写入文件 | 模板渲染到目标路径，**返回文件路径而不是内容** |
| `cred_revoke_session` | ❌ | 立即烧掉本次会话的所有短命凭证 |
| `cred_audit_query` | ❌ | 查询自己的出水记录（便于 agent 自我核对） |

**刻意不提供**：`cred_get_value`。**没有这个工具，就是整个设计的最后一道锁。**

---

## 3. 广泛对接：配方（Recipe）体系

这是把「用户想要足够广泛的对接方式」产品化的关键。**不要让 agent 自己拼命令行**，而是让凭证自带**配方**：

```yaml
# 凭证定义里的 usable_as
name: github_pat
type: api_key
value: ${GITHUB_PAT}

recipes:
  # ① 环境变量
  - id: env
    channel: exec
    template:
      env:
        GITHUB_TOKEN: "{{secret}}"
        GH_TOKEN: "{{secret}}"

  # ② 文件（一次性 fd）
  - id: file
    channel: fd
    template:
      files:
        "{{dest}}": "#{{secret}}"   # # = 落临时 inode，0600，进程退出即消失

  # ③ git credential helper
  - id: git
    channel: exec
    template:
      cmd: git
      env:
        GIT_ASKPASS: "{{helper}}"
        GITHUB_TOKEN: "{{secret}}"

  # ④ SSH 私钥
  - id: ssh
    channel: fd
    template:
      env:
        SSH_AUTH_SOCK: "{{agent}}"       # ssh-agent 转发，私钥永不离开工具
      cmd: ssh

  # ⑤ docker / kubeconfig
  - id: kubeconfig
    channel: render
    template:
      out: "~/.kube/config"
      mode: "0600"
      ttl: "30m"        # 自动删除
```

**Agent 侧体验**：

```
agent: cred_describe("secret://github_pat/api_key")
→ { recipes: ["env", "file", "git"], example: "cred_inject_exec(ref=..., recipe='git', cmd='git', args=['clone', DEST])" }
```

**Agent 不需要理解凭证是什么、怎么拼接，只需要「选一个配方，告诉我目标」。** 这正是你说的「知道如何将保存的凭证对接到具体的程序」——**对接知识沉淀在配方里，不在 agent 的脑子里。**

---

## 4. 安全性：本地优先，可撤销

### 4.1 存储

| 层 | 方案 | 理由 |
|---|---|---|
| 加密 | **AES-256-GCM**（age / XChaCha20-Poly1305 可选） | 经过检验，开销小 |
| 主密钥 | **不存磁盘**：以「解封（unseal）」形式在启动时提供；或交由 OS 密钥环（macOS Keychain / Windows DPAPI / Linux Secret Service） | 防止「拷走整个目录」即失守 |
| 备份 | 加密导出，主密钥不随备份 | |
| 传输 | 本地 unix socket + `SO_PEERCRED`（Linux）/ `LOCAL_PEERCRED`（macOS）校验对端 UID；或 mTLS | 拒绝任何非本机他用户 |

> **可直接借鉴**：HashiCorp Vault 的 Shamir 解封 / 自动解封；1Password 的 SRP + 本地解密；Infisical 的 machine identity + token。**

### 4.2 权限模型（Policy）

```yaml
# 一条策略 = 谁 + 能对哪个凭证 + 做哪种交付
- subject: agent:claude-code/*
  credential: project:myapp/*
  allow:
    channels: [exec, fd]         # ★ 不允许 render / stdout
    recipes:  [env, file]
  constraints:
    max_ttl: 8h
    dest_paths: ["${PROJECT}/**"]  # 文件只能落项目目录内
    require_approval: false
  audit: full

- subject: agent:claude-code/*
  credential: prod:*
  allow: {channels: []}            # 完全禁止
```

**关键约束**：
- **`channels` 白名单**是核心控制点——不给 `stdout` 和 `http`，就堵死了「真值进 agent 上下文」的主干道。
- **`dest_paths`** 防止渲染到 `/tmp` 或 `.git/`。
- **`require_approval`** 让生产凭证走人工审批（human-in-the-loop）。

### 4.3 必须承认的残余风险（写进文档，别藏）

1. **A1/A2 交付后，如果目标程序是 agent 能改的（比如 `node app.js` 里 agent 可以加一行 `console.log(process.env.PG_PASSWORD)`），则失效。** 这是分发式架构的固有上限。
   → 缓解：目标命令用**白名单 + 固定参数**，不允许 agent 传任意 `cmd`；A3 用短命凭证。
2. **B3 管道在同 UID 下无隔离。** → 走 `SO_PEERCRED` + 单次 + 短命。
3. **本地工具被攻陷 = 全失。** → 主密钥不进磁盘、进程硬化、最小依赖。

**一句话总结这个架构的能力边界**：

> **它把「凭证存在于 agent 的上下文/磁盘/env」变成「凭证只在两个可信进程之间的一次握手」，并且这次握手是可见、可审计、可撤销的。它不能保证「agent 完全不知道凭证存在过」。**

---

## 5. MCP 形态 vs 独立 CLI 形态

**建议两个都给，但主次分明**：

```
                ┌──────────────┐
   Agent  ──MCP──│  wellspring-mcp     │  ← 语义层：列凭证、描述、发起注入
   (LLM)         └──────┬───────┘
                        │ 本地 unix socket（同一个二进制）
                ┌───────▼──────┐
                │  wellspringd       │  ← 守护进程：解密、策略、审计、审计落库
                │  (daemon)    │
                └───────┬──────┘
                        │
              ┌─────────┴─────────┐
        wellspring CLI（人/脚本用）   Web UI（人用）
```

**为什么不是纯 MCP**：
- MCP 工具只能传**字符串参数**，没法传二进制（证书、p12、kubeconfig），B/A 类「文件交付」在 MCP 里表达得很别扭 → **用 URI + 配方绕过去**；
- 有些场景 agent 没有 MCP 通道（CI、cron），CLI 更自然；
- CLI 是一个「不依赖 LLM」的最小实现，便于先跑通。

**所以**：`wellspringd` 是唯一的真相源；MCP 和 CLI 都只是它的两个前端。**这一点决定了架构不侵入**——你的项目只需要 `pip install` / `npm i` 一个客户端，或者干脆用 `wellspring exec` 包一层。

---

## 6. Web 管理面（人看的）

| 页面 | 内容 |
|---|---|
| **凭据库** | 分组、搜索、轮换状态、过期提醒 |
| **授权策略** | 给 agent / 项目 / 人配置 subject×credential×channel |
| **实时出水（Audit）** | 可点击的具体交付：谁→哪个凭证→哪个进程→结果；一键 revoke |
| **用量统计** | 按凭证 / 项目 / agent / 时间维度的使用频次与异常 |
| **审计导出** | OCSF / JSONL，接 SIEM（参考 OWASP ACS 的 OTel 思路） |

**高亮一条**：「明文出水事件」（`stdout` / `http` 通道）用红色单独列出，当作系统的一个失败信号，用来衡量你们流程的健康度。

---

## 7. 为什么不直接买现成的

| 现成方案 | 缺什么 |
|---|---|
| **Infisical Agent Vault** | 是**代理**（拦截式），正是你说太重的那类；且不会做 A1/A2 的精准交付 |
| **HashiCorp Vault** | Dynamic Secrets 很强，但没有「agent 语义层 + 配方 + MCP」，运维重 |
| **Doppler / 1Password** | 只有「注入到 env」（B1），没有描述符隔离，没有 MCP 语义 |
| **Docker MCP Gateway** | 只管 MCP server 的 secret，无法给本地程序交付 |
| **Metorial / Arcade** | 托管 SaaS，不解决本地交付与管道 |

**空缺正是你描述的东西**：一个「凭证-目标程序」的**通用对接器**，把对接知识（配方）产品化，用 MCP + CLI + UI 三面暴露。

---

## 8. 迭代路线建议

```
Phase 0（1 周，验证核心假设）
  · wellspringd 守护进程 + 本地 socket
  · wellspring exec（A1：env 注入到子进程）
  · 3 个 MCP 工具：cred_list / cred_describe / cred_inject_exec
  · 验证：一个 node 脚本能连 DB，但 agent 上下文里没有密码

Phase 1（2-3 周）
  · fd 通道（A2）+ 模板渲染（C1，含路径白名单）
  · AES-256-GCM + OS keychain 主密钥
  · 最小 Web UI：凭据列表 + 审计流水
  · 配方体系（env / file / git / ssh-agent）

Phase 2（1 月+）
  · 策略引擎（channels / paths / TTL 白名单）
  · A3 短命凭证（AWS STS / 动态 DB 账号）
  · Web：统计、审批流、SIEM 导出
  · D2 secret URI 解析器（支持写进 .env.tpl / k8s yaml）

Phase 3（可选）
  · 团队/多租户
  · 与 CI OIDC 联邦（D4）
  · SSO + 角色
```

---

## 9. 一句话总结

> **你要的不是在网络上设关卡，而是给凭证装水表：水（凭证）存在一个加密水池里，水管（配方）决定了怎么把水引到哪个龙头（目标程序），agent 只能控制水阀（选配方 + 选目标），看不到水本身，而每一次放水都在水表上留刻度（审计）。**

---

# 增补 A：项目定位扩展 —— 从「凭证」到「敏感信息」（依据 m00190）

用户在 m00190 明确：**项目不光保存凭证，用户的姓名、地址等隐私（PII）也要保存**。这改变了信息分级模型。

## A.1 两类信息，两种暴露策略

| | **Credential（凭证）** | **PII（个人隐私数据）** |
|---|---|---|
| 例子 | API key、DB 密码、SSH 私钥、签名密钥 | 姓名、地址、电话、邮箱、身份证号 |
| 泄漏后果 | 被冒用（攻击者用它做事） | 被滥用（隐私、合规风险） |
| Agent 需要看到吗 | **永远不需要看到完整值** | **经常需要看到**（比如「给张三发货」要写地址） |
| 正确策略 | 只交付，不展示 | **脱敏展示 + 按需精确取用** |
| 检测方式 | 机器可判（凭证形态） | 上下文相关（同一段话在 A 场景是 PII，在 B 不是） |

**关键洞察**：PII 与凭证的安全目标根本不同。凭证的敌人是「被读」；PII 的敌人是「被一次性拿走全部」。所以 PII 的核心不是「不给看」，而是**最小化视图**：

```
Agent 要给客户发货 → 只需要：收件人（姓名）+ 地址 + 电话
                    不需要：身份证号、生日、历史订单
```

因此引入第三种访问模式。

## A.2 三种访问模式（覆盖凭证 + PII）

| 模式 | Agent 得到什么 | 适用 | MCP 工具 |
|---|---|---|---|
| **deliver（交付）** | 无明文；真值直达目标程序 | 凭证、密钥 | `pii_deliver` / `cred_inject_exec` |
| **view（脱敏视图）** | `张*` `138****5678` `北京市朝阳区***` | PII 的默认访问 | `pii_view` |
| **resolve（精确取值）** | 完整明文，**带用途声明与审计** | 必须写明文时（打印面单） | `pii_resolve(reason="shipping_label")` |

**设计要点**：
- `view` 是 PII 的默认答案——agent 问「张三的电话」先得到脱敏形式，够用就不升档；
- `resolve` **必须带 `reason`**，且在 Web UI 用**橙色事件**展示（比凭证红色事件低一档，但高于普通）；
- `reason` 支持策略白名单：`shipping_label` 允许，`bulk_export` 一律拒绝；
- **限速**：单个 session 对 `resolve` 设频次上限（如 10 次/分钟），拦「拖库式」枚举。

## A.3 隐私数据存储结构

```yaml
subject: person:zhang_san          # 一条 PII 记录挂在一个主体下
fields:
  name:      { value: 张三, class: pii, mask: keep1 }
  phone:     { value: "13812345678", class: pii, mask: phone }
  address:   { value: "北京市朝阳区…", class: pii, mask: region }
  id_number: { value: "110101…", class: pii_high, mask: none }  # 高敏，禁止 view，只能 deliver/受限 resolve
delivery:
  - recipe: shipping_label          # 发货场景打包：姓名+地址+电话
    fields: [name, address, phone]
```

## A.4 合规加分项（后续路线）

- **数据驻留**：PII 记录可标记「不出本机/不出本区域」；
- **删除权**：主体级一键清除（含备份轮换）；
- **分级策略模板**：GDPR/PIPL 常见字段分类预置。

---

# 增补 B：命名与品牌（m00190 要求）

## B.1 定名：**Wellspring（涌泉）**

域名/npm 冲突已手工核查（well-spring、wellspring-cli 无主流占用）。候选与落选理由：

| 候选 | 落选原因 |
|---|---|
| Waterworks | 偏市政工程感，且品牌名复数不优雅 |
| Aqueduct | 暗示集中调度，但发音拗口，且强调「引水到城」的宏大感 |
| Cistern（蓄水池） | 「存」有余，「护」不足 |
| Keychain / Vault | 与 Apple / HashiCorp 撞名 |
| Fount | 太接近 font（字体），搜索不友好 |

**Wellspring 的语义恰好覆盖产品本质**：
- **Well（井）**：一个有边界、有盖子、受保护的空间 → 加密存储与策略；
- **Spring（泉）**：水自己涌出来的、源源不断 → 按需交付、短命凭证；
- 一词双关恰好对应**「存」与「取」**两端；比「Waterworks」（水利设施）更有生命感，也更像软件名。

**术语表（文档与代码统一用词）**：
- 水源 Spring → 一条敏感信息（凭证或 PII）
- 水井 Well → 加密存储与守护进程（守护进程名 `wellspringd`）
- 配方 Recipe → 交付通道模板
- 出水 Draw → 一次交付/访问事件（审计单元，原名 DrawEvent 改为 **DrawEvent**）

## B.2 图标（已产出 design/brand/logo-wellspring.svg，512px 渲染验证通过）

视觉元素与语义映射：
- **断成三段的圆环**：有缺口 = 有入口；但环完整 = 边界受控；
- **井中的水面 + 涟漪**：存储的敏感信息；每次取用泛起涟漪（审计）；
- **升起的一滴水**：被取走的一份信息（一次 Draw）；
- **水面之下的锁孔**：受控与钥匙（策略/解密）；
- 配色 mint → turquoise → blue 渐变：水的「洁净—深藏」隐喻。

## B.3 技术栈定案（m00190 第 3 点）

- **Node.js + Bun**：运行时选 Bun（单可执行文件 `bun build --compile` 分发，跨平台，内置 SQLite/Wasm 支持）；
- MCP server 用官方 TypeScript SDK（Bun 兼容）；
- 守护进程 `wellspringd`：Bun + 本地 unix socket + napi-rs 可选绑定系统 Keychain；
- 加密：`@noble/ciphers`（纯 JS，审计友好）AES-256-GCM / XChaCha20；
- Web UI：Vite + React（或直接 Bun serve 静态产物）。
