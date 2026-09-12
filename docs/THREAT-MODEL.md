# Threat Model — Chat On Steroids security hardening

This document is the Phase 1 deliverable of the `security-hardening` branch. It maps the
system's trust boundaries, lists where model-generated content reaches high-privilege
execution, and grades the findings that the later phases address. Line references are to
the commit this branch started from.

## 1. Architecture

Chat On Steroids (CoS) is an Electron app that turns a ChatGPT conversation into a local
coding agent. Five processes cooperate:

```
ChatGPT web (remote)
   │  MCP over HTTPS (OpenAI tunnel / cloudflared / manual)
   ▼
Core/Desktop/Plugins MCP endpoints  ←—— loopback 127.0.0.1, per-surface 256-bit path token
   │                                  (src/main/mcp/server.ts)
   ▼
Electron main process
   ├── sandboxed filesystem tools  → approved roots only (src/main/sandbox.ts)
   ├── exec_command / write_stdin  → real shell, full user privileges (src/main/codex/)
   ├── desktop control             → whole-desktop input/capture (src/main/computer/)
   ├── plugin child processes      → stdio MCP servers as the OS user (src/main/plugins/)
   └── Chrome extension bridge     → loopback HTTP + WS (src/main/bridge.ts)
                                      ▲
ChatGPT tab in the user's browser ────┘  (extension/background.js, token after /pair)
```

The renderer is a sandboxed local page (contextIsolation on, nodeIntegration off,
navigation denied everywhere) that talks to the main process over zod-validated,
fixed-name IPC channels (`src/main/ipc.ts`).

### Trust boundary matrix

| # | Boundary | Direction | What crosses it | Authenticated by |
|---|----------|-----------|-----------------|------------------|
| 1 | ChatGPT → MCP endpoint | remote→local | tool calls (model output) | per-surface 256-bit path token, Host+Origin loopback checks |
| 2 | Extension → bridge | local browser→local app | ChatGPT observations, pairing | Bearer token from `/pair`, Origin must be chrome-extension or absent |
| 3 | Renderer → main | in-app | settings, roots, plugin install | none (single window, local file, navigation denied) |
| 4 | Main → OS | local | fs writes, shell, input injection | capability checkboxes + approved roots |
| 5 | Main → plugin children | local | env, stdio JSON-RPC | none (same user) |
| 6 | Main → GitHub | outbound | update check/download | TLS + SHA-256 from same release |

### Where model output becomes system effect

1. `exec_command` (`src/main/mcp/tools-core.ts:649`) — model text → real shell argv
   (`deriveExecArgs`, spawn in `src/main/codex/unified-exec.ts:309`). Not confined to
   approved roots; documented as intentional (SECURITY.md "Expected limitations").
2. `write_stdin` (`tools-core.ts:914`) — model text → keystrokes into a *live* shell
   session; bypasses any check applied only at `exec_command` time.
3. Filesystem tools (`read`/`apply_patch`/`create`/`move`/`delete`) — confined by
   `sandbox.ts` realpath containment (strong).
4. Desktop tools (`tools-desktop-windows.ts`, `tools-desktop-macos.ts`) — model input →
   synthetic mouse/keyboard on any window of the desktop, `launch_app` starts any
   executable.
5. `agents` spawn/finish (`agents.ts:1255`) — model directs new ChatGPT worker chats that
   inherit *every* capability the prime has.
6. Plugin tools (`tools-plugins.ts`) — model output → third-party MCP server process.

### Prompt-injection view

Everything the agent reads — file contents, terminal output, web pages via the browser
extension, plugin results, README files in a repository — is untrusted data that the model
then acts on with the tools above. The only real defense is that *the execution layer*
(not the model) must refuse operations beyond what the user granted. Today that layer
checks only coarse capability booleans; there is no risk classification, no audit trail,
no per-agent degradation, and no resource budget.

## 2. Security findings (pre-hardening)

### Critical

| ID | Finding | Location |
|----|---------|----------|
| C1 | `exec_command` has no risk classification. With `command` enabled (default on fresh installs, `config.ts:174-176`), one prompt-injected sentence in a README reaches full user-privilege shell: `rm -rf`, registry writes, credential dumps, `curl \| sh`. The only mitigations are a 30s default timeout and output caps. | `tools-core.ts:678`, `exec.ts`, `unified-exec.ts` |
| C2 | Loop mode is designed to never stop and has **no budget of any kind**: no iteration cap, no tool-call cap, no runtime cap, no spend cap. An injected loop runs until the user notices. | `goal.ts:210-265,297-298` |
| C3 | Workers inherit every capability of the prime (capabilities are global config read per request). A compromised worker chat has the same shell/desktop power as the user's own chat. | `agents.ts:832-858`, `mcp/server.ts:287-314` |
| C4 | `write_stdin` sends arbitrary model text into a live shell; any gate implemented at `exec_command` only is bypassable through it. | `tools-core.ts:914` |

### High

| ID | Finding | Location |
|----|---------|----------|
| H1 | Desktop control has no application allowlist and no sensitive-window protection: password managers, banking apps, system settings can be driven; `launch_app` starts any executable. | `computer/windows-apps.ts:86-123`, `helper.ts` |
| H2 | Bridge accepts *any* `chrome-extension://` origin and has no Host-header check; `/pair` mints a fresh token for any local process. A malicious extension with 127.0.0.1 host permission is fully equivalent to the real extension. | `bridge.ts:649-657,1391-1405` |
| H3 | IPC handlers never check `event.sender` (ipc.ts:366 discards the event). Combined with `plugins:install` accepting `command` + args, a renderer compromise is arbitrary command execution. | `ipc.ts:366-382`, `plugins-ipc.ts:27`, `installer.ts:130-132` |
| H4 | Plugin child processes run as the user with no isolation and can read the safeStorage blob (DPAPI user-scoped) → all stored keys, bridge token included. | `plugins/manager.ts:590-770`, `secrets.ts:21` |
| H5 | Fresh installs enable every capability (incl. `command`, `control` on Windows) with `readOnly:false` and multi-agent on with unattributed calls allowed. | `config.ts:174-189,470-484` |
| H6 | exec child environment inherits the whole `process.env` minus five named keys; any other credential in the user's environment (cloud CLIs, CI tokens) is handed to model-chosen processes. | `exec.ts:67-74,102-113` |
| H7 | No structured security audit log exists — permission decisions and dangerous tool calls are reconstructible only from the verbose session recording. | — |

### Medium

| ID | Finding | Location |
|----|---------|----------|
| M1 | Session recording stores shell output, file contents and screenshots verbatim, unencrypted; credential redaction covers only OpenAI `sk-` shapes (GitHub/AWS/Anthropic/Google patterns pass). | `session/store.ts:46-64`, `redaction.ts:6-8` |
| M2 | `roots:addPath` approves any absolute directory (e.g. the user profile root) as a sandbox root from the renderer. | `ipc.ts:547-550`, `sandbox.ts:422` |
| M3 | `sessions:dropFiles` accepts raw path strings and stages files outside approved roots. | `ipc.ts:781-784`, `input-attachments.ts:46` |
| M4 | Update chain verifies SHA-256 from the same GitHub release it downloads from; no signature. A GitHub/release compromise runs an arbitrary NSIS installer at quit. | `update.ts:262-324` |
| M5 | Tunnel binary (`cloudflared`/tunnel-client) located via PATH/user path with no hash check; a planted binary inherits `CONTROL_PLANE_API_KEY`. | `tunnel/locate.ts:85-147`, `tunnel/index.ts:502-519` |
| M6 | Cloudflared quick-tunnel URL *is* the only authorization; secret lives in a URL pasted through ChatGPT/Cloudflare, rotates only on app restart. | `tunnel/index.ts:725-734` |
| M7 | `secret:set` lets the renderer swap API keys with no re-auth (key exfiltration is blocked, key *substitution* is not). | `ipc.ts:592-608` |
| M8 | Agent/runtime primitives have no per-run aggregate budget: worker *slots* are per-run, but total runs and lifetime workers are unbounded. | `agents.ts:1345-1379` |

### Low

| ID | Finding | Location |
|----|---------|----------|
| L1 | `/hello` on the bridge is unauthenticated and unrate-limited (version disclosure). | `bridge.ts:1340-1355` |
| L2 | CSP allows `style-src 'unsafe-inline'`. | `index.ts:399` |
| L3 | Plugin npm installs don't pin `--registry`; a user-level `.npmrc` can redirect resolution. | `installer.ts:215-248` |
| L4 | Durable state files and config.json are written without restrictive file modes. | `durable.ts`, `config.ts:671-681` |

### Explicitly out of scope / accepted by upstream design

- Approved-root containment is not a kernel sandbox; same-user filesystem races are
  documented as accepted (SECURITY.md).
- The tunnel and ChatGPT/OpenAI infrastructure are out of scope per SECURITY.md.
- OS-level process isolation for plugins (job objects/seatbelt) is an architecture change;
  this branch mitigates the env/secrets surface instead and documents the residual risk.

## 3. Hardening plan (mapped to findings)

| Phase | Deliverable | Fixes |
|-------|-------------|-------|
| Security primitives | `src/main/security/`: risk levels, shell command classifier, structured audit log, extended credential redaction | C7/H7/M1 |
| Policy engine | Capability policy engine in `kernel.dispatch`: worker degradation, shell level gate (0-3), desktop gates, loop budget — enforced in code at the tool layer | C1-C4, H5, M8 |
| Shell levels | `security.shellLevel` 0-3 with allowlist for level 1, dangerous-pattern refusal at ≤2, classification also on `write_stdin` | C1, C4 |
| Env hygiene | Pattern-based scrub of credential-bearing env names for exec children | H6 |
| Desktop gates | Sensitive-app denylist (password managers, UAC, settings) + optional per-user app allowlist for control actions and `launch_app` | H1 |
| Bridge/IPC | Host-header check on the bridge, IPC sender validation, plugin install auditing | H2, H3, L1 |
| Loop budget | Per-run budget: tool calls, exec calls, runtime; exhausted budget stops the loop | C2, M8 |
| Docs | `SECURITY-HARDENING.md` review of every change, defaults and residual risks | — |
