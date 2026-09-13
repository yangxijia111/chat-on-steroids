# Security Hardening Review — `security-hardening` branch

This is the deliverable of the systematic security hardening pass described in
`docs/THREAT-MODEL.md`: Phase 1 (§§1-9) and the Phase 2 second-iteration pass (§10-12).
Sections follow the requested review format: architecture, threat model, findings, new
security architecture, code changes, tests, remaining risks, breaking changes and
recommended defaults.

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

---

## 10. Phase 2 — second hardening iteration

Phase 2 addresses the tier of gaps Phase 1's decision model could not express
(`docs/THREAT-MODEL.md` §4, findings P2-1…P2-10). The uniform decision model is now:

```text
Principal + Workspace Trust + Capability + Tool descriptor + Shell classification
+ Approval policy + Automation budget
```

enforced in `kernel.dispatch` / `checkToolPolicy` and the execution modules — never in
prompt text, never as `if (tool === 'xxx')` special cases.

### What changed

| Area | Change |
|------|--------|
| Shell level 1 | Strictly near-read-only: read-only git queries, file reads, version checks. `project-code-execution` (npm test/ci/run, npx, node -e/scripts, pytest, vitest, jest, make/ninja/msbuild, cargo/go/dotnet, cmake --build, tsc, RunUAT/Unity, wrapper shells) is refused at level 1 and additionally gated by workspace trust. |
| Workspace trust | New `security.workspaceTrust` (`untrusted \| trusted \| full`, default `trusted` to preserve existing behaviour). `untrusted` refuses the project-code-execution category at *any* shell level, including `write_stdin` into a live shell — building a hostile repository runs code its authors left in it. |
| git hardening | `-c` config injection (case-sensitive `-c`, not `-C`), `--exec-path`, `--paginate`, `--ext-diff`, `--textconv` downgrade git commands out of the level-1 allowlist (`git-unsafe-extension`, medium). Exec children get `GIT_PAGER=cat`, `PAGER=cat`, `GIT_EDITOR=:`. |
| Tool descriptors | `src/main/security/tool-descriptors.ts` — one `ToolSecurityDescriptor` table (capabilities, risk, network, filesystem, processExecution, desktopControl, workerPolicy) for core *and* plugin tools. `descriptorFor()` returns a fail-closed `UNKNOWN_TOOL_DESCRIPTOR` for unlisted names; restricted workers are denied plugin tools by default; plugin self-reported annotations are not a security boundary. A coverage test walks the core/desktop surface tool lists so new tools must register a descriptor. |
| Critical approval | `src/main/security/approval.ts` — credential access, privilege escalation, destructive system operations, persistence, obfuscated commands, download-and-execute and security software changes (new `security-software` critical category) require an Electron dialog (Allow once / Allow for session / Deny) even at shell level 3. No window / dialog failure / 120 s timeout ⇒ Deny. Session approvals cache by tool+category+rule; concurrent identical requests share one prompt; every decision is audited. |
| Desktop fail-closed | Allowlist matching is exact executable basename or exact full path (case/slash-normalised string equality) — no prefix matching. With an allowlist configured, input/capture/launch refuse unconfirmable targets (no window id, unresolvable window, missing process name). Windows refuses windowless/unresolvable calls in restricted mode; macOS gates `launch_app` and probes the active window for focusless input batches in restricted mode (the no-probe contract is preserved when no allowlist is set). |
| Run-level budget | Budget scope is `run:<runId>` for swarm conversations — prime and every worker share one counter, and a worker cannot escape it by opening a new conversation (armed detection includes the prime's goal switch). Standalone Goal/Loop chats use `conv:<id>`. New dimensions: `maxWorkerSpawnsPerRun`, `maxDesktopActionsPerRun`, `maxFileWritesPerRun` (from tool descriptors) alongside tool calls, execs and runtime. |
| Security UI | New Security tab: shell level, workspace trust, level-1 prefix list, worker permissions, desktop allowlist, the six budget numbers and the audit switch, saved through the validated `settings:save` security section with the same three-way merge as every other group. Presets: **Safe** (level 1, untrusted, tight budget), **Development** (level 2, trusted — the highlighted recommendation), **Full Automation** (level 3, full, inherit, wide budget — never the default). |
| Audit wiring | `recordSecurityAudit` reads `security.auditLog` from the live config on every entry; `initAuditLog` no longer snapshots it (it runs before `loadConfig()`). `auditLog: false` now survives restarts and runtime changes apply immediately. |
| Bridge pairing | Pairing is desktop-initiated: `bridge:startPairing` mints a one-time 256-bit code (5-minute TTL, consumed on success) shown in Setup; the extension popup gains a code field (visible only when the app answers `pairing_required`) and latches its automatic retry off until a code arrives. `/pair` requires an explicit Origin; the first successful pairing pins that extension's origin and different extensions are refused until Disconnect clears the token latch, the pin and any in-flight code together. Bridge protocol 14. |
| IPC frame gate | Handlers require `event.senderFrame === event.sender.mainFrame` and `senderFrame.url === ` the URL the live main window's main frame loaded. Unknown/nested/navigated frames deny with the same `Untrusted IPC sender` reply. |
| CI gates | `security-audit` job runs `scripts/audit-production.mjs` (`npm audit --omit=dev`, high+, exceptions must be recorded with GHSA id and reason — currently only the documented sharp 0.35.3 libheif pin). CodeQL (`security-extended`, secret detection included) on push/PR/weekly. Dependency Review on PRs (fails on high+). GitHub push-protection secret scanning is a repository setting to enable (free for public repos). |

### Phase 2 module map

| Module | Role |
|--------|------|
| `security/tool-descriptors.ts` | **New** — the single tool security metadata table; fail-closed for unknown names |
| `security/approval.ts` | **New** — local human confirmation for the seven critical categories |
| `security/shell-policy.ts` | Level-1 near-read-only allowlist, `project-code-execution`, `git-unsafe-extension`, `security-software` |
| `security/policy.ts` | Workspace-trust gate, descriptor-driven worker degradation, critical-approval verdicts, run-scoped budget charges |
| `security/loop-budget.ts` | Run aggregation (`run:`/`conv:` scopes), spawn/desktop/write dimensions |
| `security/desktop-gate.ts` | Exact allowlist matching, fail-closed unknown targets |
| `security/audit.ts` | Live-switch reading (no startup cache) |
| `renderer/security.ts` + Security tab | Settings UI with presets |
| `extension/{background,popup}.{js,html}` | Protocol 14: popup code field, needs-code latch, code-carrying pair message |

## 11. Phase 2 tests

New/extended suites (all green alongside the existing 1,100+ tests):

- `security-shell-policy.test.ts` — level-1 read-only matrix, project-code-execution
  classification (25+ commands incl. `node -e`, `npx`, `npm ci`, `make`, `msbuild`,
  `pytest`, `RunUAT.bat`, `tsc`, wrapper shells), git unsafe extensions (`-c` vs `-C`,
  `--ext-diff`, `--textconv`, `--paginate`, `--exec-path`) and their safe counterparts,
  security-software criticals.
- `security-policy.test.ts` — workspace-trust gate across shell levels and `write_stdin`.
- `security-tool-descriptors.test.ts` — core/desktop surface coverage, fail-closed
  unknown names, plugin tools denied for restricted workers, inherit opt-out.
- `security-approval.test.ts` — the seven categories request approval at level 3,
  high-but-not-critical passes without one, deny/once/session semantics, rule-keyed
  session cache, fail-closed on missing window/prompt failure, concurrent de-duplication.
- `security-env-desktop.test.ts` — exact-match allowlist (prefix no longer matches),
  path-entry matching, unknown-target refusal in restricted mode.
- `security-loop-budget.test.ts` — run-scope sharing (prime + workers, new-conversation
  escape closed), spawn/desktop/write exhaustion, scope mapping.
- `security-audit.test.ts` — auditLog switch read live (runtime off/on).
- `security-settings-ui.test.ts` — paints/reads every control, presets write the ladder,
  clamping, dirty-field guard, save entry point.
- `bridge.test.ts` — pairing_required / pairing_invalid / replay / no-Origin / pinned
  origin / Disconnect-clears-pin; extension protocol-14 metadata and popup code-field
  assertions.
- `ipc.test.ts` — nested frame, rogue main-frame URL, missing senderFrame all refused;
  trusted renderer path intact.

Run results (2026-09-13 re-verification, Windows, suite split into two halves to
avoid the machine's parallel-run resource contention): all suites green except
four environment-inherent failures that reproduce identically on the unmodified
pre-hardening base commit `86d7014` — `mcp.test.ts` ×2 (CI discovery-size budget
plus one batch-parser note) and `windows-keys.test.ts` ×1 (PowerShell script
parsing on this locale) and `search.test.ts` ×1 (ripggrep file-count accounting
on this machine). `npm run typecheck` passes. Two follow-up fixes from this
re-verification: `input-delivery-integration.test.ts` now pairs through the
desktop-started one-time code and the IPC frame gate (protocol-14 change had
missed its bridge/IPC stubs), and the bilingual README regained the Linux
`--no-sandbox` fallback note the packaging suite asserts.

## 12. Remaining risks after Phase 2 (honest list)

Phase 1 residuals (§7) mostly stand; updated status first, then the new ones.

1. **Classifier is heuristic, not a parser** (unchanged). Novel encodings at level 3
   still reach the approval dialog rather than being auto-classified — which is now a
   human decision point instead of silent execution, but the *classification* itself can
   still miss.
2. **Plugin processes still run as the OS user.** The restricted-worker gate now refuses
   plugin tools, but a *prime* chat calling a plugin still executes third-party code with
   full user rights. OS-level isolation (job objects / seatbelt) remains the upstream
   architecture change.
3. **Bridge pairing pins one extension id.** A user who legitimately switches browsers
   or reloads the extension as a different id must Disconnect and re-pair. The code is
   shown in the app and typed in the popup — shoulder-surfing on a shared screen is a
   (thin) new surface; the 5-minute TTL and one-time use bound it.
4. **Desktop allowlist is opt-in.** Without a configured allowlist, unresolvable desktop
   targets still fall through to the native layer's consistency checks (preserves
   existing behaviour); sensitive-app denial still applies whenever the process name is
   known. macOS focusless input stays unprobed in the unrestricted mode (documented
   Phase 1 residual).
5. **Run-level budget is in-memory.** A crash mid-run resets the counters (armed goal
   switches survive; the spent budget does not). A hostile loop that can crash the app
   could restart its budget — but crashing the app also kills the loop's tool access
   until re-arm, which requires the durable switch.
6. **Approval dialog timeouts deny, but the dialog itself can linger** if the user never
   answers; the tool result is already a refusal after 120 s and the stale dialog click
   is discarded (audited as the decision it produced).
7. **Update chain / tunnel binary / sharp 0.35.3 pin** — unchanged from §7.5-§7.7; the
   sharp exception is the single recorded entry the CI audit gate acknowledges.
8. **Workspace trust is a global setting, not per-root.** `untrusted` is meant for the
   "examining an unfamiliar repository" session; the natural follow-up is per-root trust
   recorded when a folder is approved.
9. **`workspaceTrust` defaults to `trusted`** (compatibility with level-2 installs where
   `npm test` already worked). Fail-closed would break every existing user's build on
   upgrade; the Safe preset and the untrusted option are the expressed tightening path.
