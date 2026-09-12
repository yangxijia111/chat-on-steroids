# Security Hardening Review — `security-hardening` branch

This is the final deliverable of the systematic security hardening pass described in
`docs/THREAT-MODEL.md`. Sections follow the requested review format: architecture,
threat model, findings, new security architecture, code changes, tests, remaining
risks, breaking changes and recommended defaults.

## 1. Architecture (post-hardening)

```
ChatGPT web ──MCP/HTTPS(tunnel)──> per-surface MCP endpoint (127.0.0.1, 256-bit path token)
                                        │
                                        ▼
                              kernel.dispatch  ─────────── ① checkToolPolicy  (NEW, in code)
                                        │                      ├─ shell level 0–3 + command classifier
                                        │                      ├─ worker permission degradation
                                        │                      └─ Goal/Loop safety budget
                                        ▼
                              capability guard (existing) ─── sandbox.resolvePath (existing)
                                        │
              ┌─────────────────────────┼──────────────────────────┐
              ▼                         ▼                          ▼
        filesystem tools          exec_command/write_stdin    desktop tools
        (approved roots only)     (real shell, classified)    (② desktop target gate, NEW)
                                        │                          │
                                        ▼                          ▼
                              ③ scrubbed child env         sensitive-app denylist +
                              (NEW)                        optional app allowlist

Chrome extension ──HTTP/WS──> bridge (127.0.0.1, bearer token, Origin allowlist
                              + loopback Host check ④ NEW)
Renderer ──IPC──> main (zod schemas + ⑤ sender validation NEW)
Every decision ──> ⑥ security/audit.jsonl (NEW, redacted, rotated)
```

The enforcement points ①–⑥ all live in code that actually executes tools, never in
prompt text. The model is treated as an untrusted proposer throughout.

## 2. Threat model

See `docs/THREAT-MODEL.md` for the full trust-boundary analysis (14 components,
data-flow matrix, prompt-injection view). Summary of pre-hardening risk:

- **Critical** — unclassified `exec_command` (C1), budget-free Loop mode (C2),
  full-power workers (C3), `write_stdin` as a classification bypass (C4).
- **High** — no desktop app allowlist/sensitive-app protection (H1), bridge accepts
  any extension origin + no Host check (H2), unvalidated IPC senders and a
  renderer-reachable command-install channel (H3), unisolated plugin processes (H4),
  all-capability fresh installs (H5), credential-bearing exec environment (H6),
  no audit trail (H7).
- **Medium/Low** — session-recording redaction gaps, update/tunnel integrity gaps,
  root-approval breadth, unauthenticated `/hello`, CSP nuance, npm registry pinning.

## 3. Security findings (with resolutions)

| ID | Severity | Finding | Status on this branch |
|----|----------|---------|----------------------|
| C1 | Critical | `exec_command` = prompt injection → full-user shell | **Fixed**: `security.shellLevel` 0–3; command classifier refuses high/critical at default level 2; allowlist-only at level 1 (`src/main/security/shell-policy.ts`, enforced in `policy.ts` via `kernel.dispatch`) |
| C2 | Critical | Loop mode never stops, no budget | **Fixed**: per-run budget (tool calls / execs / runtime), enforced at the tool gate and on the draft path (`security/loop-budget.ts`, `goal.ts`) |
| C3 | Critical | Workers inherit every capability | **Fixed**: `workerPermissions: 'restricted'` default — workers keep read/search/lifecycle tools, lose write/exec/desktop (`policy.ts`) |
| C4 | Critical | `write_stdin` bypasses any exec-time check | **Fixed**: typed input is classified too; short y/n answers still pass; dangerous typed lines refused |
| H1 | High | Desktop control unrestricted; `launch_app` any exe | **Fixed (Windows, full)**: sensitive apps (password managers, UAC/logon, settings) hard-denied for input/capture/launch; optional `desktopAppAllowlist` restricts the rest. **Partial (macOS)**: focus + capture targets gated; unfocused input documented as residual risk |
| H2 | High | Bridge: any `chrome-extension://` origin, no Host check | **Mitigated**: loopback Host header now required (DNS-rebinding layer). Accepting any extension origin remains by design (documented residual risk) |
| H3 | High | IPC handlers never check `event.sender` | **Fixed**: every handler validates `event.sender.id` against the main window's webContents |
| H4 | High | Plugin processes run as user, inherit env | **Mitigated**: plugin env was already allowlist-based (verified + tested); OS-level isolation remains out of scope (documented) |
| H5 | High | Fresh installs enable every capability | **Partially addressed**: shell level 2 and restricted workers are secure defaults for every install. The first-launch capability checkboxes are a product decision left unchanged (documented in Breaking Changes) |
| H6 | High | exec children inherit credential-bearing env | **Fixed**: name-pattern scrub (KEY/TOKEN/SECRET/… + cloud prefixes) for exec children and the desktop helper (`exec.ts`, `computer/index.ts`); explicit caller overrides still pass and are audited |
| H7 | High | No security audit trail | **Fixed**: `security/audit.jsonl` — timestamp/session/agent/tool/action/target/risk/decision/reason, secret-redacted, size-capped with rotation |
| M1 | Medium | Recording redaction only knows `sk-` shapes | **Fixed**: redaction covers OpenAI/Anthropic/OpenRouter/GitHub/AWS/Slack/Google/Stripe/Bearer shapes (`redaction.ts`) |
| L1 | Low | `/hello` unauthenticated | Accepted (identification-only response); Host check now bounds it |
| — | Medium | sharp 0.35.3 libheif advisory (GHSA-rgj7-g3m4-5g8c) | **Not bumped**: the native-source compliance inventory pins 0.35.3 and regenerating it is the maintainers' reviewed release process. Advisory recorded here; fix is `sharp@0.35.4` + regenerated `docs/licenses/native/sources.json` |
| — | Medium | Transitive `hono` (MCP server chain) | **Fixed**: lockfile updated to 4.13.7; `npm audit --omit=dev` now reports 0 vulnerabilities |

Dev-only advisories (`@xmldom/xmldom`, `fast-uri`, `js-yaml` under vitest) do not
ship in the packaged app and are left for the maintainers' dev-dependency cycle.

## 4. New security architecture

Design principles applied: least privilege, default deny, explicit consent,
defense in depth, fail closed, **no LLM as a security boundary**, auditability,
workspace isolation, capability-based security, secure defaults.

New modules under `src/main/security/`:

| Module | Role |
|--------|------|
| `shell-policy.ts` | Pure command classifier: 14 categories × 4 risk levels, POSIX + PowerShell/cmd spellings, user-extendable allowlist; danger patterns outrank allowlists |
| `policy.ts` | The single decision point called from `kernel.dispatch` for every tool call: shell levels, worker degradation, loop budget, audit emission |
| `loop-budget.ts` | Per-armed-run counters (tool calls, execs, wall clock) shared by the policy gate and the goal draft path |
| `desktop-gate.ts` | Sensitive-app hard denylist (not config-overridable) + optional app allowlist semantics |
| `audit.ts` | Redacted, rotated JSONL audit log; fire-and-forget so logging can never break a tool |

Config surface (`Config.security`, zod-validated, fail-closed defaults):

```jsonc
{
  "shellLevel": 2,                       // 0 禁止 | 1 allowlist | 2 普通开发 | 3 完全
  "shellAllowlist": [],                  // 用户追加的 level-1 命令前缀（如 RunUAT.bat）
  "workerPermissions": "restricted",     // restricted | inherit
  "desktopAppAllowlist": [],             // 空 = 不限制（敏感应用硬拒绝始终生效）
  "loopBudget": { "enabled": true, "maxToolCallsPerRun": 800, "maxExecPerRun": 200, "maxRuntimeMinutes": 240 },
  "auditLog": true
}
```

UX follows the requested risk ladder: LOW (allowlisted reads, ordinary dev
commands) runs automatically at level ≥1; MEDIUM (package installs, network
fetches) runs at level ≥2; HIGH (system mutation, persistence, global installs)
needs level 3; CRITICAL (credentials, obfuscation, privilege escalation,
broad deletion, download-pipes-shell) needs level 3 **and is always audited**.

## 5. Code changes

| File | Change |
|------|--------|
| `src/main/security/{shell-policy,policy,loop-budget,desktop-gate,audit}.ts` | **New** — security primitives (see §4) |
| `src/main/mcp/kernel.ts` | `dispatch` now runs `checkToolPolicy` in the refusal cascade — every tool on every surface passes the policy gate |
| `src/shared/types.ts` | `SecuritySettings` type + `Config.security` |
| `src/main/config.ts` | Schema + secure defaults; corrupt configs already fail conservative |
| `src/main/exec.ts` | `scrubSecretEnv` exported; `childEnv` scrubs credential-shaped inherited vars (explicit overrides still honoured) |
| `src/main/computer/index.ts` | Desktop helper env scrubbed the same way |
| `src/main/mcp/tools-desktop-windows.ts` | `resolveDesktopGate` before every input/capture/launch; window lookup shared with the browser-chord check (single helper roundtrip) |
| `src/main/mcp/tools-desktop-macos.ts` | Gate on explicit `focus` and capture targets; ordinary-key batches never ask about windows (existing contract preserved) |
| `src/main/goal.ts` | Loop draft refuses to continue once the budget is exhausted |
| `src/main/bridge.ts` | `hostIsLoopback` — non-loopback Host headers get 403 `forbidden_host` |
| `src/main/ipc.ts` | `handle()` validates `event.sender` against the main window; refusals logged |
| `src/main/redaction.ts` | Extended credential shapes (9 provider patterns, Bearer masking) |
| `src/main/index.ts` | `initAuditLog(userData/security)` |
| `package.json` / lockfile | Transitive `hono` audit fix (sharp deliberately kept at the reviewed 0.35.3 pin — see §7) |
| Tests | `security-{shell-policy,policy,loop-budget,audit,env-desktop,bridge-host}.test.ts` **new**; exec mocks extended for `scrubSecretEnv`; `agents`/`ipc`/`input-delivery` suites adapted to the sender gate and explicit hardening opt-outs |

Commits on `security-hardening` are small and individually reviewable:
`docs: add threat model…`, `security: add shell risk classifier…`,
`security: add capability policy engine…`, `security: scrub credential-shaped env…`,
`security: enforce desktop target gate…`, `security: require loopback Host…`,
`security: validate IPC sender…`, `security: apply transitive hono audit fix`,
plus two follow-up test/gate-scope fixes.

## 6. Tests

New suites (165 assertions across 6 new files + updated desktop suites):

- `security-shell-policy.test.ts` (96) — destructive/credential/obfuscated/
  privilege/pipe-execute patterns (POSIX + PowerShell + cmd), allowlist behaviour
  (including `git -C`, `npm run <script>` scoping), user allowlist extension,
  quote/case evasion, level matrix.
- `security-policy.test.ts` (14) — level 0–3 enforcement through the engine,
  batch worst-member rule, `write_stdin` bypass closure + short-answer carve-out,
  worker degradation matrix, `inherit` opt-out, prime/ordinary-chat exemption.
- `security-loop-budget.test.ts` (7) — counters, per-conversation isolation,
  disabled budget, and end-to-end denial through `checkToolPolicy` with an armed
  goal switch; goal-draft refusal.
- `security-audit.test.ts` (13) — structured fields, credential redaction in every
  free-text field, extended redaction shapes, logger JWT masking.
- `security-env-desktop.test.ts` (10) — env scrub matrix + override pass-through,
  sensitive-app hard deny (incl. path-qualified names), allowlist enforcement,
  read-method exemption.
- `security-bridge-host.test.ts` (6) — loopback Host accepted; rebound/absent
  Host refused (`forbidden_host`) with and without Origin.

Run results on this machine (Windows, full suite in two halves):
**176/177 test files pass; 1,125+ tests green.** The only failures are
`mcp.test.ts` (2 tests: a CI-tuned discovery-size budget of 3,800 bytes vs 3,851
actual, and one batch-parser note) and `windows-keys.test.ts` (1 test needing
PowerShell `Add-Type` C# compilation) — **verified to fail identically on the
unmodified base commit** (`86d7014`, clean worktree), i.e. pre-existing
environment-specific failures, not regressions. `mcp-shutdown.test.ts` passes
(2/2). `npm run typecheck`, `verify:notices` and `verify:privacy` all pass;
`npm audit --omit=dev` reports **0 vulnerabilities**.

## 7. Remaining risks (honest list)

1. **Classifier is heuristic, not a parser.** Shell text classification catches the
   documented dangerous shapes; a determined adversary with level-3 access or a
   novel encoding can get past regexes. It is defense-in-depth on top of the
   capability gate and the workspace cwd — never the only layer. Level 3 is an
   explicit user decision.
2. **Plugin processes still run as the OS user.** Same-user processes (any plugin,
   any exec child at level ≥2) can read the safeStorage blob on Windows
   (DPAPI user-scope) and thus stored keys. Real isolation needs job objects /
   seatbelt — an architecture change recommended for upstream, out of scope here.
   Env surface is now scrubbed; secrets handed *to* plugins by design remain
   visible to those plugins.
3. **Bridge still trusts any `chrome-extension://` origin.** Extension ids are not
   knowable in advance for unpacked installs; a malicious extension with
   127.0.0.1 host permission remains equivalent to the real one. Host + Origin +
   token bound the web-page and rebound-domain threats only.
4. **macOS desktop: unfocused input batches are not pre-checked** against the
   sensitive-app list (the "never ask about the window" contract forbids the
   foreground probe). The helper's own assertInputTarget still enforces
   correctness; focus/capture targets are policy-gated. Windows is fully gated.
5. **Update chain has SHA-256 but no signature**; the manifest travels with the
   artifacts. A GitHub-compromise still yields code execution at quit. Adding
   `verifySignature` plumbing (defined in the review as the follow-up interface)
   requires a signing identity the project does not have yet.
6. **Tunnel binary located via PATH/user path without hash check** (unchanged);
   same-user plant risk. URL-as-token for cloudflared quick tunnels is unchanged
   upstream design.
7. **sharp 0.35.3 libheif advisory** left on the reviewed pin; fix requires the
   maintainers' native-source inventory regeneration (see §3).
8. **`roots:addPath` still approves any absolute directory** (user-consented
   action in the UI); with the IPC sender gate a compromised renderer would have
   to be the app's own page. A confirmation dialog for roots outside the home
   profile is a worthwhile upstream follow-up.
9. Session recording remains local, verbatim and unencrypted (upstream design);
   redaction coverage improved but shell output can still echo secrets typed
   interactively.

## 8. Breaking changes

Behavioural changes an existing user will notice, all deliberate:

1. **Shell level 2 by default**: system-changing / credential-touching /
   obfuscated / broad-deletion commands now return `SHELL_LEVEL_TOO_LOW` instead
   of running. Ordinary development (git, npm test/build, npm install, cargo,
   dotnet, cmake, curl fetches) is unaffected. Users who want the old behaviour
   set shell level 3.
2. **Workers are read-only by default** (`WORKER_PERMISSION_REQUIRED` refusals for
   exec/apply_patch/desktop). `workerPermissions: 'inherit'` restores the old
   behaviour; `agents`/`session_finish`/read tools always work.
3. **Goal/Loop runs stop at the budget** (800 tool calls / 200 execs / 240 min per
   armed run) with a clear stop message. Raise or disable in settings.
4. **Non-loopback Host headers are refused by the bridge** — affects only clients
   that were never the extension.
5. **Exec children no longer see credential-shaped environment variables**
   (`*_TOKEN`, `AWS_*`, `SSH_AUTH_SOCK`, …). Toolchains relying on such variables
   must pass them explicitly (allowed, and audited).
6. **Desktop control of password managers / sign-in & UAC / system settings is
   hard-denied on Windows** and for focused/captured targets on macOS. There is
   no configuration override by design.
7. Test-suite adjustments (documented above) opt specific suites back into the
   pre-hardening behaviour to keep testing lifecycle semantics; security
   behaviour is covered by the new suites.

## 9. Recommended defaults

```jsonc
// config.json → security (current shipped defaults, kept for review)
{
  "shellLevel": 2,
  "shellAllowlist": [],
  "workerPermissions": "restricted",
  "desktopAppAllowlist": [],
  "loopBudget": { "enabled": true, "maxToolCallsPerRun": 800, "maxExecPerRun": 200, "maxRuntimeMinutes": 240 },
  "auditLog": true
}
```

- For a trusted single-user workstation doing routine coding: keep everything at
  these defaults; raise `shellLevel` to 3 only for a session that genuinely needs
  system-level commands, then lower it again.
- For engine/creative workflows (Unreal/Unity/Blender), put the build commands
  into `shellAllowlist` and the editors into `desktopAppAllowlist` instead of
  raising the global level.
- For unattended overnight Loop runs, consider tightening the budget before
  arming the loop.
- Keep `readOnly: true` for exploring an unfamiliar repository.
