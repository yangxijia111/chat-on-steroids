/**
 * Shell 命令风险分级 — exec_command / write_stdin 的执行前分类层。
 *
 * 威胁模型（docs/THREAT-MODEL.md C1/C4）：模型输出经 prompt injection 可携带任意
 * shell 文本，而 `command` capability 只是一个总开关。本模块在 spawn 之前给每条
 * 命令一个风险等级和类别，供 security/policy.ts 按 security.shellLevel 执行：
 *
 *   level 0 — 禁止 shell；
 *   level 1 — 只放行 allowlist 内的低风险读/构建命令；
 *   level 2 — 额外放行普通开发命令；high/critical 拒绝；
 *   level 3 — 全部放行，但 critical 仍写入审计日志。
 *
 * 这是纵深防御的一层，不是唯一边界（cwd 沙箱、capability、审计同时生效）。
 * 分类器刻意保守：无法识别的输入按 medium 归类（level 2 放行、level 1 拒绝），
 * 规则同时覆盖 POSIX 与 PowerShell/cmd 拼写，并对引号/大小写不敏感。
 */

import type { ShellType } from '../codex/shell.js';

export type ShellRiskLevel = 'low' | 'medium' | 'high' | 'critical';

export type ShellCategory =
  | 'allowlisted'
  | 'normal'
  | 'package-install'
  | 'network-fetch'
  | 'global-install'
  | 'system-mutate'
  | 'privilege-escalation'
  | 'credential-access'
  | 'obfuscated'
  | 'pipe-execute'
  | 'destructive'
  | 'persistence'
  | 'container-privileged'
  | 'unclassified';

export interface ShellClassification {
  level: ShellRiskLevel;
  category: ShellCategory;
  /** 命中规则的简短说明，进入审计日志与拒绝文案。 */
  rule: string;
}

const CATEGORY_LEVEL: Record<ShellCategory, ShellRiskLevel> = {
  allowlisted: 'low',
  normal: 'medium',
  'package-install': 'medium',
  'network-fetch': 'medium',
  'global-install': 'high',
  'system-mutate': 'high',
  'privilege-escalation': 'critical',
  'credential-access': 'critical',
  obfuscated: 'critical',
  'pipe-execute': 'critical',
  destructive: 'critical',
  persistence: 'high',
  'container-privileged': 'high',
  unclassified: 'medium'
};

/** 归一化：折叠空白，保留原始字符以匹配路径/凭据模式。 */
function normalize(command: string): string {
  return command.replace(/\s+/g, ' ').trim();
}

/** 去掉 token 两端的引号，便于程序名识别。 */
function unquote(token: string): string {
  let value = token;
  while (value.length > 1 && (/^['"]/.test(value) || /['"]$/.test(value))) {
    value = value.replace(/^['"]/, '').replace(/['"]$/, '');
  }
  return value;
}

/** 程序名（第一个 token，去引号去路径，小写，去 .exe 后缀）。 */
function programOf(normalized: string): string {
  const first = unquote(normalized.split(' ')[0] ?? '');
  const base = first.replaceAll('\\', '/').split('/').pop() ?? '';
  const lower = base.toLowerCase();
  return lower.endsWith('.exe') ? lower.slice(0, -4) : lower;
}

// --------------------------------------------------------------------- allowlist

/** 表示「任意参数皆低风险」的哨兵。 */
const ANY = '*';

/**
 * Level 1 放行的低风险命令：程序 → 允许的参数前缀集合（'*' 表示任意）。
 *
 * 刻意不含 `git clean`/`git reset --hard`（破坏性）、`npm install`（写依赖并触发
 * 任意 postinstall）、`curl`/`wget`（网络）。用户可经 security.shellAllowlist
 * 追加（例如 Unreal/Unity 的受控构建命令），追加项与内置项同权限。
 */
const SAFE_PROGRAM_ARGS: Record<string, readonly string[]> = {
  git: ['status', 'diff', 'log', 'show', 'branch', 'remote', 'ls-files', 'rev-parse', 'blame', 'describe', 'tag', 'shortlog', 'merge-base', 'grep', 'stash list'],
  'git.exe': ['status', 'diff', 'log', 'show', 'branch', 'remote', 'ls-files'],
  ls: [ANY], dir: [ANY], pwd: [ANY], tree: [ANY], du: [ANY], df: [ANY],
  wc: [ANY], head: [ANY], tail: [ANY], cat: [ANY], echo: [ANY],
  which: [ANY], where: [ANY], type: [ANY], file: [ANY], stat: [ANY],
  grep: [ANY], findstr: [ANY], rg: [ANY],
  node: ['--version', '-v', '-e', '--check'],
  // 注意：npm/pnpm 的 'run' 不在原始前缀列表里 —— run 必须走脚本名约束分支。
  npm: ['test', 'ci', 'ls', '--version'],
  npx: [ANY],
  pnpm: ['test', 'lint', 'build', '--version', 'why'],
  yarn: ['test', 'lint', 'build', '--version'],
  cargo: ['test', 'build', 'check', 'clippy', 'fmt', 'tree', 'metadata', '--version'],
  rustc: ['--version'],
  dotnet: ['test', 'build', 'restore', 'format', '--version', '--list-sdks'],
  cmake: ['--build', 'build', '--version', '-S', '-B', '-E'],
  make: [ANY],
  ninja: [ANY],
  msbuild: [ANY],
  pytest: [ANY], 'py.test': [ANY],
  python: ['--version', '-V', '-m pytest', '-m pip list', '-m pip show'],
  python3: ['--version', '-V', '-m pytest', '-m pip list'],
  pip: ['list', 'show', '--version'],
  go: ['test', 'build', 'vet', 'fmt', 'version'],
  mvn: ['test', 'compile', 'verify'],
  gradle: ['test', 'build', 'tasks', '--version'],
  javac: [ANY], java: ['-version', '--version'],
  tsc: [ANY], vitest: [ANY], jest: [ANY],
  'get-childitem': [ANY], 'get-content': [ANY], 'get-item': [ANY], 'select-string': [ANY],
  'measure-object': [ANY], 'get-command': [ANY], 'get-variable': [ANY],
  'test-path': [ANY], 'get-filehash': [ANY]
};

/** npm/pnpm/yarn run 允许的内置脚本名。 */
const SAFE_RUN_SCRIPTS = new Set(['test', 'lint', 'build', 'typecheck', 'check', 'dev', 'start', 'format', 'audit', 'e2e']);

/** git 等程序允许全局 flag 前置（git -C path status）。 */
const GLOBAL_FLAG = /^(-(?!-)[a-z]+|--[a-z][a-z-]*(=.*)?)$/i;

/** 用户追加的 allowlist（security.shellAllowlist），前缀匹配、大小写不敏感。 */
function matchesUserAllowlist(normalized: string, userAllowlist: readonly string[]): string | null {
  const lower = normalized.toLowerCase();
  for (const entry of userAllowlist) {
    const prefix = entry.trim().toLowerCase();
    if (prefix.length === 0) continue;
    if (lower === prefix || lower.startsWith(`${prefix} `)) return entry;
  }
  return null;
}

function isAllowlisted(normalized: string, program: string, userAllowlist: readonly string[]): ShellClassification | null {
  const userHit = matchesUserAllowlist(normalized, userAllowlist);
  if (userHit !== null) return { level: 'low', category: 'allowlisted', rule: `user allowlist: ${userHit.slice(0, 80)}` };

  const allowed = SAFE_PROGRAM_ARGS[program];
  if (!allowed) return null;
  const tokens = normalized.split(' ').map(unquote);
  const args = tokens.slice(1).map((token) => token.toLowerCase());
  if (allowed.includes(ANY) || args.length === 0) {
    return { level: 'low', category: 'allowlisted', rule: `program allowlist: ${program}` };
  }
  const first = args[0] ?? '';
  // 版本类 flag 本身就在 allowlist 里（node --version / cmake --build）。
  if (allowed.includes(first)) {
    return { level: 'low', category: 'allowlisted', rule: `program allowlist: ${program} ${first}` };
  }
  // npm run <script>：脚本名受集合约束。
  if ((program === 'npm' || program === 'pnpm' || program === 'yarn') && first === 'run') {
    const script = args[1] ?? '';
    if (script && SAFE_RUN_SCRIPTS.has(script)) {
      return { level: 'low', category: 'allowlisted', rule: `script allowlist: ${program} run ${script}` };
    }
    return null;
  }
  // 全局 flag（-C <path>、--no-pager 等）及其取值之后找到的第一个子命令决定类别。
  let flagValue = false;
  const firstSubcommand = args.find((token) => {
    if (flagValue) {
      flagValue = false;
      return false;
    }
    if (GLOBAL_FLAG.test(token)) {
      // -C/--git-dir 这类带独立取值的 flag，跳过下一个 token。
      flagValue = token.toLowerCase() === '-c';
      return false;
    }
    return true;
  });
  if (firstSubcommand !== undefined && allowed.includes(firstSubcommand)) {
    return { level: 'low', category: 'allowlisted', rule: `program allowlist: ${program} ${firstSubcommand}` };
  }
  return null;
}

// --------------------------------------------------------------------- patterns

interface PatternRule {
  category: ShellCategory;
  rule: string;
  pattern: RegExp;
}

/**
 * 危险模式表。按严重度从高到低排列；第一条命中决定分类。
 * 危险模式优先于 allowlist：`git log -- .ssh` 仍命中 credential-access。
 * 正则针对已归一化空白的文本执行。
 */
const DANGER_PATTERNS: readonly PatternRule[] = [
  // ---- critical
  // 下载管道执行最先判定（比通用 iex 规则更具体，两者同为 critical）。
  { category: 'pipe-execute', rule: '下载管道执行', pattern: /\b(curl|wget|invoke-webrequest|iwr|invoke-restmethod)\b[^|;]{0,300}\|\s*[^|;]{0,40}\b(sh|bash|zsh|powershell|pwsh|cmd|iex|invoke-expression|python)\b/i },
  { category: 'credential-access', rule: 'SSH/云凭据材料', pattern: /(\.ssh[\/\\]|id_rsa|id_ed25519|authorized_keys|\.aws[\/\\]credentials|\.aws[\/\\]config|\.azure[\/\\]|\.gcloud[\/\\]|\.kube[\/\\]config|\.netrc|\.docker[\/\\]config\.json|\.git-credentials|\.pypirc)/i },
  { category: 'credential-access', rule: '浏览器配置/凭据转储', pattern: /(login data|cookies\.sqlite|key4\.db|logins\.json|user data[\/\\](default|profile)|credential manager|cmdkey|lsass|mimikatz|procdump)/i },
  { category: 'obfuscated', rule: 'PowerShell 编码命令', pattern: /(^|\s)-(encodedcommand|enc|e)\s+[a-z0-9+/=]{16,}/i },
  { category: 'obfuscated', rule: 'Base64 解码执行', pattern: /(frombase64string\(|base64\s+--?decode\s*\|[^|;]{0,20}(sh|bash|zsh)|echo\s+[a-z0-9+/=]{40,}\s*\|\s*(sh|bash))/i },
  { category: 'obfuscated', rule: '动态拼接执行', pattern: /(^|[\s;|&])(iex|invoke-expression)\b/i },
  { category: 'privilege-escalation', rule: '提权执行', pattern: /(^|[\s;|&])(sudo|doas|sudoedit|gsudo)\b|(^|[\s;|&])su\s+(root|-)|\brunas\b|start-process\s+[^|;]{0,120}-verb\s+runas/i },
  { category: 'destructive', rule: '广域递归删除', pattern: /\b(rm|rmdir)\b[^|;&]{0,40}\s(--recursive|--force|-rf|-fr|-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*)[^|;&]{0,40}\s?(\/([a-z.]+)?(\s|$)|~|\$home|%userprofile%|c:\/|c:\\\\?|\/etc|\/usr|\/var|\/home)/i },
  { category: 'destructive', rule: '整树强删（PowerShell/cmd）', pattern: /(remove-item\b[^|;&]{0,120}(-recurse[^|;&]{0,80}-force|-force[^|;&]{0,80}-recurse))|\brd\s+\/s\b|\bdel\s+\/[a-z]*s\b|\berase\s+\/s\b/i },
  { category: 'destructive', rule: '磁盘/分区破坏', pattern: /(^|[\s;|&])(format(\.com)?\s|diskpart\b|mkfs(\.\w+)?\s|dd\s+[^|;]{0,120}of=\/dev\/(disk|sd|nvme|hd|mapper))/i },
  { category: 'destructive', rule: '系统关停', pattern: /(^|[\s;|&])(shutdown|poweroff|halt|reboot)\b|\bstop-computer\b|\brestart-computer\b/i },

  // ---- high
  { category: 'system-mutate', rule: '注册表写入', pattern: /(^|[\s;|&])(reg(\.exe)?\s+(add|delete|import|restore)|regedit\s+\/s|\bset-itemproperty\b[^|;&]{0,80}(hklm|hkcu|hkcr):|\bnew-itemproperty\b[^|;&]{0,80}(hklm|hkcu):)/i },
  { category: 'system-mutate', rule: '系统服务/驱动变更', pattern: /(^|[\s;|&])(sc(\.exe)?\s+(config|create|delete|stop|start)|\bnew-service\b|\bremove-service\b|(^|[\s;|&])net\s+(start|stop)\s|systemctl\s+(disable|enable|mask|stop|restart)|bcdedit|bootrec)/i },
  { category: 'system-mutate', rule: '系统组件/策略变更', pattern: /(^|[\s;|&])(sfc\s|dism\s|wsl\s+(--unregister|--install)|set-executionpolicy|set-mppreference|netsh\s+(advfirewall|winhttp)\s+(set|reset))/i },
  { category: 'persistence', rule: '计划任务持久化', pattern: /(schtasks(\.exe)?\s+\/(create|change|delete)|register-scheduledtask|(^|[\s;|&])crontab\s|\/etc\/cron|new-scheduledtaskaction)/i },
  { category: 'persistence', rule: '启动/登录脚本持久化', pattern: /(\.bashrc|\.zshrc|\.bash_profile|\.profile\b|powershell_profile|currentversion\\run|shell:startup)/i },
  { category: 'container-privileged', rule: '容器特权/宿主挂载', pattern: /docker\s+(run|create)[^|;]{0,240}(--privileged|--pid=host|--network=host|--cap-add=(sys_admin|net_admin)|-v\s+\/\s*:)/i },
  { category: 'global-install', rule: '全局/系统包安装', pattern: /(npm\s+(\w+\s+){0,2}-g\s|npm\s+(install|i)\s+--global|pip3?\s+[^|;]{0,40}--user\s|pipx\s+install|cargo\s+install\b|choco\s+install|winget\s+install|scoop\s+install|apt(-get)?\s+install|brew\s+install|yum\s+install|dnf\s+install|pacman\s+-s)/i },

  // ---- medium
  { category: 'package-install', rule: '项目内包安装', pattern: /(npm\s+(install|i|add)\b|pnpm\s+(install|add)\b|yarn\s+(install|add)\b|pip\s+install\s|uv\s+(add|pip\s+install)|poetry\s+add|bundle\s+install|composer\s+(install|require)|nuget\s+restore)/i },
  { category: 'network-fetch', rule: '网络取数', pattern: /(^|[\s;|&])(curl|wget)(\.exe)?\s|\binvoke-webrequest\b|\binvoke-restmethod\b|(^|[\s;|&])iwr\s/i },
  { category: 'system-mutate', rule: '网络栈变更', pattern: /(netsh\s+interface\s+(ip|ipv4)\s+set|route\s+(add|delete)|ipconfig\s+\/(release|renew)|new-netfirewallrule|set-netfirewallprofile)/i }
];

// --------------------------------------------------------------------- classifier

export interface ClassifyOptions {
  shellType?: ShellType;
  /** security.shellAllowlist 的用户追加项。 */
  userAllowlist?: readonly string[];
}

/**
 * 分类一条命令。先扫危险模式，再查 allowlist；其余按 medium 处理
 * （level 2 放行普通开发命令，level 1 拒绝）。
 */
export function classifyShellCommand(command: string, options: ClassifyOptions = {}): ShellClassification {
  const normalized = normalize(command);
  if (normalized === '') return { level: 'low', category: 'normal', rule: 'empty command' };
  for (const { category, rule, pattern } of DANGER_PATTERNS) {
    if (pattern.test(normalized)) return { level: CATEGORY_LEVEL[category]!, category, rule };
  }
  const program = programOf(normalized);
  const allowlisted = isAllowlisted(normalized, program, options.userAllowlist ?? []);
  if (allowlisted) return allowlisted;
  return { level: CATEGORY_LEVEL.unclassified, category: 'unclassified', rule: `unclassified program: ${program}` };
}

/** 一个 shell 级别是否放行某风险等级。level 0 一律拒绝。 */
export function shellLevelAllows(shellLevel: number, level: ShellRiskLevel): boolean {
  if (shellLevel >= 3) return true;
  if (shellLevel === 2) return level === 'low' || level === 'medium';
  if (shellLevel === 1) return level === 'low';
  return false;
}

/** 生成 level 0-2 的统一拒绝文案。 */
export function shellLevelRefusal(shellLevel: number, classification: ShellClassification): string {
  if (shellLevel <= 0) {
    return 'SHELL_DISABLED: command execution is disabled for this app (security shell level 0). Ask the user to raise the shell level in Settings.';
  }
  if (shellLevel === 1) {
    return `SHELL_LEVEL_TOO_LOW: this command is not on the low-risk allowlist for shell level 1 (read-only VCS and build/test commands). Classify the work differently, or ask the user to raise the shell level in Settings.`;
  }
  return `SHELL_LEVEL_TOO_LOW: this command is classified ${classification.level} (${classification.rule}); shell level 2 permits only ordinary development commands. Ask the user to raise the shell level in Settings if this command is genuinely intended.`;
}
