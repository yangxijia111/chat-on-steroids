<p align="center"><img src="docs/images/readme-hero.svg?v=2" width="960" alt="Turn ChatGPT into Codex without touching Codex limits. Chat On Steroids: Your files. Your terminal. Your ChatGPT plan." /></p>

<h1 align="center">Chat On Steroids (CoS)</h1>

<p align="center">
  <a href="#中文">中文</a> ·
  <a href="#english">English</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT" /></a>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg" alt="Platform" />
  <img src="https://img.shields.io/badge/status-beta-orange.svg" alt="Beta" />
  <img src="https://img.shields.io/badge/UI-%E4%B8%AD%E8%8B%B1%E5%8F%8C%E8%AF%AD-informational.svg" alt="UI: 中英双语" />
</p>

<p align="center"><strong>一个本地编码桥接器：让 ChatGPT 直接读写你的文件、运行终端命令、控制桌面 —— 不消耗 Codex 配额。</strong><br />本仓库在上游项目的基础上完成了一轮系统性安全加固（详见 <a href="#中文">中文</a> / <a href="#english">English</a> 说明）。</p>

---

## 中文

### 📖 项目简介

Chat On Steroids（CoS）是一个 Electron 桌面应用 + Chrome 伴侣扩展的组合，通过 MCP（Model Context Protocol）把 ChatGPT 网页版接入你的本地开发环境。它让 ChatGPT 能够在**你批准的文件夹**内读写文件、运行命令、保持终端会话，甚至控制桌面（屏幕、鼠标、键盘），并把这些真实工具结果回传到对话中。

- **使用你已有的 ChatGPT 会话**，不消耗 Codex 配额（账号的模型可用性、用量与上下文限制仍然生效）。
- 内置能力限制模型：所有文件工具强制约束在批准的目录根内，凭据使用操作系统安全存储，历史记录仅保存在本地。
- 本仓库基于上游 [totec448-spec/chat-on-steroids](https://github.com/totec448-spec/chat-on-steroids)（v2.0.9），并在 `security-hardening` 分支上完成了一轮系统性安全加固。

> 本项目与 OpenAI 无关，也未获其背书。ChatGPT 和 Codex 是 OpenAI 的商标。

### ✨ 功能特性

- **真实本地工作**：文件读写与补丁、真实 Shell 终端、测试运行、生成的文件下载、会话历史与任务计划。
- **Worker 团队**：把独立任务拆分给多个并行 Worker（默认 2 个，最多 8 个），Worker 完成后保留上下文，可继续复用。
- **长任务控制**：
  - **Goal**：由模型判定任务是否真正完成；
  - **Loop**：在既定指令范围内持续工作；
  - **Compact & Resume**：把会话与 Worker 历史压缩交接到一个全新对话中继续；
  - 任务运行中可随时插入修正指令。
- **桌面控制（Desktop 连接器）**：屏幕检查、鼠标、键盘与剪贴板（Windows / macOS，macOS 需显式启用并授予系统权限）。
- **插件系统（Plugins 连接器）**：接入外部 MCP 工具（Blender、Playwright、Memory、Fetch 等），支持经过审核的插件目录、自定义本地/远程服务器与 OAuth。
- **Code 模式**：将本地工具与插件工具合并到一次 JavaScript 调用中，支持保存任务计划与后台命令结果。
- **简体中文界面**与完善的模型/推理等级选择器（跟随登录账号的可用模型）。
- **安全加固（本仓库新增）**：见下方[核心功能说明](#-核心功能说明)。

### 📸 截图与演示

<p align="center"><a href="docs/images/demo.mp4"><img src="docs/images/demo.gif" width="800" alt="Chat On Steroids 演示：模型选择、任务计划、实时工具结果与可复用 Worker" /></a></p>

<details>
<summary>更多截图</summary>

![会话、Worker 与任务计划](docs/images/workspace.png)

![模型与推理等级选择](docs/images/model-picker.png)

![文件夹与能力设置](docs/images/settings.png)

</details>

### 🧰 环境要求

**日常使用**

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Windows 10/11、macOS 13 Ventura 及以上、主流桌面 Linux |
| 浏览器 | Chrome 116+ 或最新版 Edge（加载伴侣扩展） |
| 账号 | 支持 Developer mode 与自定义 MCP 应用的 ChatGPT 账号/工作区 |

**从源码构建**

| 项目 | 要求 |
| --- | --- |
| Node.js | 20.19+ 或 22.12+（构建工具链 Vite 7 的要求） |
| 包管理器 | npm（仓库内含 `package-lock.json`，请使用 `npm ci`） |

> 安装包说明：上游发布的安装包目前为未签名 beta（Windows 未做发布者签名，macOS 未公证），请对照 Release 中的校验和验证。Linux 需要 Secret Service 密钥环服务，推荐使用 DEB 包；当系统禁用非特权用户命名空间（unprivileged user namespaces）时，AppImage 启动器可回退到 `--no-sandbox` 运行。

### 📦 安装与配置

**方式一：下载安装包（推荐普通用户）**

预编译安装包由上游项目发布：前往 [上游 Releases 页面](https://github.com/totec448-spec/chat-on-steroids/releases/latest) 下载对应平台的安装包（本仓库当前不直接分发二进制安装包）。

**方式二：从源码运行**

```bash
git clone https://github.com/<你的用户名>/chat-on-steroids.git
cd chat-on-steroids
npm ci
npm run dev
```

**首次配置（应用内完成）**

1. 在 **Settings → Workspace** 批准你的项目文件夹，并审阅工具权限；
2. 在 **Settings → Setup** 配置隧道并连接 **Core** 连接器（支持 OpenAI Secure MCP Tunnel、Cloudflare quick tunnel 或自建 HTTPS 隧道），然后在 ChatGPT 的 Developer mode 中添加 **Core** 自定义应用；
3. 点击 **Open extension folder**，在 `chrome://extensions` 中以"加载已解压的扩展程序"方式加载伴侣扩展，配对自动完成；
4. 选择模型、编写任务并发送。

详细步骤与故障排查见 [docs/setup.md](docs/setup.md)。

### 🚀 使用方法

- **派发任务**：在 CoS 中选择项目与模型，像正常对话一样向 ChatGPT 描述任务，模型会通过 MCP 调用本地工具完成工作，工具结果实时回显。
- **并行 Worker**：把独立子任务交给 Worker 并行处理；完成后可向同一 Worker 发送后续任务以复用其上下文。
- **长任务**：启用 **Goal**（自动判定完成）或 **Loop**（持续迭代）；对话过长时使用 **Compact & Resume** 无缝交接。
- **桌面控制**：在设置中启用 **Desktop** 权限后，模型可以查看屏幕、移动鼠标、输入键盘与操作剪贴板。
- **只读模式**：开启后禁用一切写入、命令执行与桌面控制，适合仅让模型"看代码"的场景。
- **更新后**：重新加载 Chrome 伴侣扩展，并按提示在 ChatGPT 中刷新 CoS 应用（这是两个独立步骤）。

### 📂 项目目录结构

```
chat-on-steroids/
├── src/
│   ├── main/          # Electron 主进程：MCP 内核、执行器、桌面控制、安全策略
│   │   ├── mcp/       #   MCP 工具与内核（文件、终端、桌面等工具面）
│   │   ├── security/  #   安全加固：策略引擎、审计日志、Shell 分级、桌面门控
│   │   └── codex/     #   会话与任务管理
│   ├── preload/       # 预加载桥（渲染进程安全暴露）
│   ├── renderer/      # 界面：聊天、Agent 面板、模型选择器、i18n
│   └── shared/        # 主进程与渲染进程共享类型
├── extension/         # Chrome 伴侣扩展（内容脚本、后台、弹窗）
├── native/            # 原生组件（macOS 桌面辅助进程/插件）
├── docs/              # 设计文档、安全文档、发布说明、第三方许可证
├── scripts/           # 构建、打包、校验脚本
├── test/              # Vitest 测试（120+ 个测试文件）
└── artwork/           # 应用图标源文件
```

### 🔍 核心功能说明

**1. 安全模型（上游既有）**

- 文件工具强制约束在**批准的目录根**内；Shell 命令以普通用户权限运行；
- **只读模式**一键禁用写入、命令执行与桌面控制；
- 凭据存放在操作系统安全存储（Windows 凭据管理器 / macOS 钥匙串 / Linux Secret Service）；
- 会话历史仅存本地，默认开启录制、30 天保留。

**2. 安全加固（本仓库 `security-hardening` 分支新增）**

| 加固点 | 说明 |
| --- | --- |
| Shell 风险分级器 | 对命令进行 0–3 级风险分类，分级结果参与工具策略判定 |
| 能力策略引擎 | 统一的工具策略检查：Shell 等级限制、Worker 权限降级、Goal/Loop 安全预算 |
| 桌面目标门控 | 敏感应用（密码管理器、银行类等）拒绝清单 + 可选应用允许清单 |
| 桥接与 IPC 加固 | 扩展桥要求环回 Host 头；IPC 严格校验发送方身份 |
| 凭据脱敏 | 子进程环境变量中形似凭据的变量被自动清洗；审计日志脱敏并轮转 |
| 结构化审计日志 | 每次安全决策写入 `security/audit.jsonl`（已脱敏、按大小轮转） |

设计依据与剩余风险分析见 [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) 与 [docs/SECURITY-HARDENING.md](docs/SECURITY-HARDENING.md)。

### 🛠️ 构建、运行与打包

```bash
npm ci                # 安装依赖（锁定版本）
npm run dev           # 开发模式启动 Electron 应用
npm run typecheck     # TypeScript 类型检查
npm test              # 运行 Vitest 测试
npm run verify        # 完整校验：隐私检查 + 第三方声明 + 类型检查 + 全量测试
npm run dist:win      # 打包 Windows 安装包（x64/arm64）
npm run dist:mac      # 打包 macOS（x64/arm64）
npm run dist:linux    # 打包 Linux（x64/arm64）
```

CI 位于 [.github/workflows/](.github/workflows/)。发布产物说明见 [docs/setup.md](docs/setup.md) 与上游 Release 流程。

### 🗺️ 更新计划 / Roadmap

> 以下为意向性计划，不代表承诺；欢迎通过 Issue 讨论。

- [ ] 跟进上游 `main` 的后续版本，保持安全加固补丁的可维护性；
- [ ] 为安全策略引擎补充更多默认规则与文档（基于 [THREAT-MODEL](docs/THREAT-MODEL.md) 中列出的剩余风险）；
- [ ] 完善中英双语文档覆盖。

### 🤝 贡献说明

欢迎 Issue 与 PR。提交前请运行 `npm run verify` 确保隐私检查、第三方声明与测试全部通过。更详细的贡献流程与提交规范参见 [CONTRIBUTING.md](CONTRIBUTING.md) 与 [.githooks/](.githooks/)。

安全问题请勿直接公开提 Issue，参见 [SECURITY.md](SECURITY.md)。

### 🙏 致谢

- 本项目基于 [totec448-spec/chat-on-steroids](https://github.com/totec448-spec/chat-on-steroids) 构建，核心设计与绝大部分代码来自上游作者与[社区贡献者](CONTRIBUTORS.md)；
- 第三方组件许可清单见 [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt) 与 [docs/licenses/](docs/licenses/)；
- 感谢 OpenAI 提供 ChatGPT 与 MCP 生态（本项目与 OpenAI 无关，也未获其背书）。

### 📄 开源协议

[MIT](LICENSE) © Chat On Steroids contributors。上游代码与本仓库新增代码均以 MIT 协议发布。

---

## English

### 📖 Overview

Chat On Steroids (CoS) is an Electron desktop app plus a companion Chrome extension that connects the ChatGPT web UI to your local development environment over MCP (Model Context Protocol). It lets ChatGPT read and edit files, run commands and keep terminal sessions inside **folders you approve**, control your desktop (screen, mouse, keyboard), and follow the real tool results as they arrive in the conversation.

- **Uses your existing ChatGPT conversation** — it does not consume Codex quota (your account's model availability, usage and context limits still apply).
- Ships with a capability-limiting model: file tools are enforced to approved roots, credentials use the operating system's secure storage, and history stays local.
- This repository is based on the upstream project [totec448-spec/chat-on-steroids](https://github.com/totec448-spec/chat-on-steroids) (v2.0.9) and adds a systematic security hardening pass on the `security-hardening` branch.

> Not affiliated with or endorsed by OpenAI. ChatGPT and Codex are OpenAI trademarks.

### ✨ Features

- **Work on the real project**: file reads/patches, real shell terminals, test runs, generated-file downloads, session history and task plans.
- **Give it a team**: split independent jobs across parallel workers (2 by default, up to 8); workers keep their context so follow-up tasks can reuse them.
- **Stay in control of long tasks**:
  - **Goal** lets the model decide when the task is genuinely complete;
  - **Loop** keeps working within your brief;
  - **Compact & Resume** carries session and worker history into a fresh conversation;
  - send corrections while work is still running.
- **Desktop control**: screen inspection, mouse, keyboard and clipboard (Windows / macOS; macOS requires explicit enablement and OS permissions).
- **Plugins**: external MCP tools such as Blender, Playwright, Memory and Fetch, with a reviewed catalog, custom local/remote servers and OAuth.
- **Code mode**: combines local and plugin tools in one JavaScript call, with saved task plans and background command results.
- **Simplified Chinese UI** and a model/reasoning picker that follows your signed-in account.
- **Security hardening (new in this repository)**: see [Core functionality](#english--core-functionality).

### 📸 Screenshots & demo

<p align="center"><a href="docs/images/demo.mp4"><img src="docs/images/demo.gif" width="800" alt="Chat On Steroids in action: model selection, task plans, live tool results and reusable workers" /></a></p>

<details>
<summary>More screenshots</summary>

![Conversation, workers and task plan](docs/images/workspace.png)

![Model and reasoning selection](docs/images/model-picker.png)

![Folder and capability settings](docs/images/settings.png)

</details>

### 🧰 Requirements

**Daily use**

| Item | Requirement |
| --- | --- |
| OS | Windows 10/11, macOS 13 Ventura or newer, current desktop Linux |
| Browser | Chrome 116+ or current Edge (for the companion extension) |
| Account | A ChatGPT account/workspace with Developer mode and custom MCP apps |

**Building from source**

| Item | Requirement |
| --- | --- |
| Node.js | 20.19+ or 22.12+ (required by the Vite 7 build toolchain) |
| Package manager | npm (`package-lock.json` is committed — use `npm ci`) |

> Release notes: upstream binaries are unsigned beta builds (Windows is not publisher-signed; macOS is unsigned and unnotarized) — verify against the release checksums. Linux requires a Secret Service keyring; the DEB is preferred. When unprivileged user namespaces are disabled, the AppImage launcher can fall back to `--no-sandbox`.

### 📦 Installation

**Option 1: download a prebuilt installer (recommended for most users)**

Prebuilt installers are published by the upstream project: grab the package for your platform from the [upstream Releases page](https://github.com/totec448-spec/chat-on-steroids/releases/latest) (this repository does not distribute binaries itself).

**Option 2: run from source**

```bash
git clone https://github.com/<your-username>/chat-on-steroids.git
cd chat-on-steroids
npm ci
npm run dev
```

**First-run setup (inside the app)**

1. Approve your project folder in **Settings → Workspace** and review the tool permissions;
2. Configure a tunnel in **Settings → Setup** and connect the **Core** connector (OpenAI Secure MCP Tunnel, Cloudflare quick tunnel or your own HTTPS tunnel), then add the **Core** custom app in ChatGPT's Developer mode;
3. Click **Open extension folder**, then use **Load unpacked** in `chrome://extensions` — pairing is automatic;
4. Choose a model, write your task and send.

Full walkthrough and troubleshooting: [docs/setup.md](docs/setup.md).

### 🚀 Usage

- **Dispatch tasks**: pick a project and model in CoS, then describe the task to ChatGPT as usual — the model calls local tools over MCP and results stream back live.
- **Parallel workers**: hand independent subtasks to workers; send a follow-up to the same worker afterwards to reuse its context.
- **Long tasks**: enable **Goal** (automatic completion judgement) or **Loop** (continuous iteration); use **Compact & Resume** when the conversation grows long.
- **Desktop control**: enable **Desktop** permissions in settings and the model can inspect the screen and drive mouse, keyboard and clipboard.
- **Read-only mode**: disables writes, command execution and desktop control — ideal for "look, don't touch" reviews.
- **After updating**: reload the companion extension and refresh the CoS apps in ChatGPT when prompted (two separate steps).

### 📂 Project structure

```
chat-on-steroids/
├── src/
│   ├── main/          # Electron main process: MCP kernel, exec, desktop control, security
│   │   ├── mcp/       #   MCP tools & kernel (file, terminal, desktop tool surfaces)
│   │   ├── security/  #   Hardening: policy engine, audit log, shell classifier, desktop gate
│   │   └── codex/     #   Session & task management
│   ├── preload/       # Preload bridge (safe renderer exposure)
│   ├── renderer/      # UI: chat, agent panel, model picker, i18n
│   └── shared/        # Types shared between main and renderer
├── extension/         # Companion Chrome extension (content scripts, background, popup)
├── native/            # Native components (macOS desktop helper/addon)
├── docs/              # Design docs, security docs, release notes, third-party licenses
├── scripts/           # Build, packaging and verification scripts
├── test/              # Vitest suites (120+ test files)
└── artwork/           # App icon sources
```

### 🔍 Core functionality

**1. Security model (upstream)**

- File tools are enforced to **approved folder roots**; shell commands run with your normal user privileges;
- **Read-only mode** disables writes, command execution and desktop control in one switch;
- Credentials use the OS secure storage (Windows Credential Manager / macOS Keychain / Linux Secret Service);
- History is stored locally, with recording on and 30-day retention by default.

**2. Security hardening (new on this repository's `security-hardening` branch)**

| Hardening | Description |
| --- | --- |
| Shell risk classifier | Classifies commands into risk levels 0–3; the level feeds tool policy decisions |
| Capability policy engine | Unified tool policy checks: shell levels, worker permission degradation, Goal/Loop safety budget |
| Desktop target gate | Sensitive-app denylist (password managers, banking, …) plus an optional app allowlist |
| Bridge & IPC hardening | The extension bridge requires a loopback Host header; IPC validates the sender against the main window |
| Credential scrubbing | Credential-shaped env vars are scrubbed from child processes; the audit log is redacted and rotated |
| Structured audit log | Every security decision is appended to `security/audit.jsonl` (redacted, size-rotated) |

Rationale and remaining-risk analysis: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and [docs/SECURITY-HARDENING.md](docs/SECURITY-HARDENING.md).

### 🛠️ Build & package

```bash
npm ci                # Install dependencies (locked versions)
npm run dev           # Start the Electron app in dev mode
npm run typecheck     # TypeScript type check
npm test              # Run the Vitest suites
npm run verify        # Full gate: privacy check + third-party notices + typecheck + all tests
npm run dist:win      # Package Windows installers (x64/arm64)
npm run dist:mac      # Package macOS (x64/arm64)
npm run dist:linux    # Package Linux (x64/arm64)
```

CI lives in [.github/workflows/](.github/workflows/). See [docs/setup.md](docs/setup.md) and the upstream release process for packaging details.

### 🗺️ Roadmap

> Intent, not commitment — discussion welcome via Issues.

- [ ] Keep pace with upstream `main` while keeping the hardening patches maintainable;
- [ ] Add more default rules and documentation for the policy engine, driven by the remaining risks listed in the [threat model](docs/THREAT-MODEL.md);
- [ ] Extend bilingual documentation coverage.

### 🤝 Contributing

Issues and PRs are welcome. Please run `npm run verify` before submitting so the privacy check, third-party notices and tests all pass. See [CONTRIBUTING.md](CONTRIBUTING.md) and [.githooks/](.githooks/) for the commit conventions.

Please do not open public issues for security problems — see [SECURITY.md](SECURITY.md).

### 🙏 Acknowledgements

- This project is built on [totec448-spec/chat-on-steroids](https://github.com/totec448-spec/chat-on-steroids); the core design and the vast majority of the code come from the upstream author and [community contributors](CONTRIBUTORS.md);
- Third-party component notices: [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt) and [docs/licenses/](docs/licenses/);
- Thanks to OpenAI for ChatGPT and the MCP ecosystem (this project is not affiliated with or endorsed by OpenAI).

### 📄 License

[MIT](LICENSE) © Chat On Steroids contributors. Both the upstream code and the additions in this repository are released under the MIT license.
