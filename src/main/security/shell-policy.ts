/**
 * Shell 命令风险分级 — exec_command / write_stdin 的执行前分类层。
 *
 * 威胁模型（docs/THREAT-MODEL.md C1/C4）：模型输出经 prompt injection 可携带任意
 * shell 文本，而 `command` capability 只是一个总开关。本模块在 spawn 之前给每条
 * 命令一个风险等级和类别，供 security/policy.ts 按 security.shellLevel 与
 * security.workspaceTrust 执行：
 *
 *   level 0 — 禁止 shell；
 *   level 1 — 只放行「真正接近只读」的命令：只读 VCS 查询、文件读取、版本查询。
 *             执行项目代码的命令（npm test、make、pytest、npx、node -e …）即使
 *             参数看着无害也属于 project-code-execution，level 1 一律拒绝；
 *   level 2 — 额外放行普通开发命令；high/critical 拒绝；
 *   level 3 — 全部放行，但 critical 仍需人工确认并写入审计日志。
 *
 * workspaceTrust 是与 shellLevel 正交的第二道闸：project-code-execution 类命令
 * 还要求 workspaceTrust ≥ trusted（陌生仓库里的一次 npm test 就是执行仓库作者
 * 留下的任意代码）。
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
  | 'project-code-execution'
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
  | 'security-software'
  | 'container-privileged'
  | 'git-unsafe-extension'
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
  'project-code-execution': 'medium',
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
  'security-software': 'critical',
  'container-privileged': 'high',
  'git-unsafe-extension': 'medium',
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

/** 程序名（第一个 token，去引号去路径，小写，去 Windows 可执行后缀）。 */
function programOf(normalized: string): string {
  const first = unquote(normalized.split(' ')[0] ?? '');
  const base = first.replaceAll('\\', '/').split('/').pop() ?? '';
  const lower = base.toLowerCase();
  // .exe/.bat/.cmd 都是「直接键入即运行」的后缀，剥掉后程序表只需一份键。
  for (const suffix of ['.exe', '.bat', '.cmd']) {
    if (lower.endsWith(suffix)) return lower.slice(0, -suffix.length);
  }
  return lower;
}

// --------------------------------------------------------------------- allowlist

/** 表示「任意参数皆低风险」的哨兵。 */
const ANY = '*';

/**
 * Level 1 放行的低风险命令：程序 → 允许的参数前缀集合（'*' 表示任意）。
 *
 * 判据是「接近只读」：命令输出可以进入模型上下文，但不能让仓库内容变成
 * 可执行代码。因此刻意不含：
 *   - `npm test/ci`、`make`、`pytest`、`vitest`、`npx`、`node -e` 等一切执行项目
 *     代码的入口（见 PROJECT_CODE_PROGRAMS，它们要求 trusted 工作区 + level ≥2）；
 *   - `git clean`/`git reset --hard`（破坏性）、`npm install`（写依赖并触发
 *     任意 postinstall）、`curl`/`wget`（网络）；
 *   - git 的 config 注入与外部 diff/pager 扩展路径（见 GIT_UNSAFE_FLAGS）。
 * 用户可经 security.shellAllowlist 追加（例如 Unreal/Unity 的受控构建命令），
 * 追加项与内置项同权限。
 */
const SAFE_PROGRAM_ARGS: Record<string, readonly string[]> = {
  git: ['status', 'diff', 'log', 'show', 'branch', 'remote', 'ls-files', 'rev-parse', 'blame', 'describe', 'tag', 'shortlog', 'merge-base', 'grep', 'stash list'],
  'git.exe': ['status', 'diff', 'log', 'show', 'branch', 'remote', 'ls-files'],
  ls: [ANY], dir: [ANY], pwd: [ANY], tree: [ANY], du: [ANY], df: [ANY],
  wc: [ANY], head: [ANY], tail: [ANY], cat: [ANY],
  which: [ANY], where: [ANY], type: [ANY], file: [ANY], stat: [ANY],
  grep: [ANY], findstr: [ANY], rg: [ANY],
  // 解释器只放行版本查询 —— `-e`/脚本参数都是任意代码执行。
  node: ['--version', '-v'],
  npm: ['ls', '--version'], pnpm: ['--version'], yarn: ['--version'],
  python: ['--version', '-V', '-m pip list', '-m pip show'], python3: ['--version', '-V', '-m pip list'],
  pip: ['list', 'show', '--version'],
  rustc: ['--version'], cargo: ['--version'],
  go: ['version'], dotnet: ['--version', '--list-sdks'],
  java: ['-version', '--version'],
  'get-childitem': [ANY], 'get-content': [ANY], 'get-item': [ANY], 'select-string': [ANY],
  'measure-object': [ANY], 'get-command': [ANY], 'get-variable': [ANY],
  'test-path': [ANY], 'get-filehash': [ANY]
};

/**
 * 执行项目代码的程序：包管理器脚本入口、测试运行器、构建系统、解释器执行
 * 任意脚本、Unreal/Unity 构建工具。共同点是「仓库里的文本会变成正在运行的
 * 进程」——postinstall、conftest.py、build.rs、Makefile、自定义构建步骤、
 * RunUAT 脚本都可以是仓库任意作者留下的代码。
 *
 * 值为受控子命令（'run' 需进一步看脚本名）；ANY 表示该程序任何调用都算。
 */
const PROJECT_CODE_PROGRAMS: Record<string, readonly string[] | '*'> = {
  npm: ['test', 'ci', 'run', 'exec', 'start'],
  pnpm: ['test', 'run', 'exec', 'dlx'],
  yarn: ['test', 'run', 'dlx'],
  npx: '*',
  bunx: '*',
  // 解释器执行脚本 / -e / -m 子命令（版本查询已在 allowlist 之前放行）。
  node: '*',
  deno: '*', bun: '*',
  python: '*', python3: '*',
  // 测试运行器与任务入口。
  pytest: '*', 'py.test': '*', vitest: '*', jest: '*', mocha: '*', karma: '*',
  // 构建系统：Makefile/构建脚本本就是项目代码。
  make: '*', ninja: '*', msbuild: '*', cmake: ['--build', 'build'],
  cargo: '*', rustc: '*',
  go: '*', dotnet: '*',
  gradle: '*', mvn: '*', bazel: '*', buck: '*',
  tsc: '*', webpack: '*',
  // Unreal / Unity 构建链。
  runuat: '*', unrealbuildtool: '*', unity: '*', unityhub: '*',
  // 包装 shell：参数是脚本文件或 -c/-Command 代码时执行的是项目/任意代码。
  sh: '*', bash: '*', zsh: '*', dash: '*', pwsh: '*', powershell: '*'
};

/** git 只读子命令允许的全局 flag（git -C path status）。 */
const GLOBAL_FLAG = /^(-(?!-)[a-z]+|--[a-z][a-z-]*(=.*)?)$/i;

/**
 * git 的潜在执行路径 flag：config 注入（-c core.pager=… / diff.*.command=…）、
 * 外部 diff/textconv、pager、exec-path。在 allowlist 判定前检查；命中即降为
 * medium（level 1 拒绝、level 2 放行并审计）。--no-* 变体是显式关闭扩展，
 * 天然不命中这些模式。
 */
const GIT_UNSAFE_FLAGS: readonly RegExp[] = [
  // -c 是 config 注入，必须与小写 c 精确匹配：-C <path> 是常用且安全的目录切换。
  /(^|\s)-c\s/,
  /(^|\s)--exec-path(=|\s|$)/i,
  /(^|\s)--paginate\b/i,
  /(^|\s)--ext-diff\b/i,
  /(^|\s)--textconv\b/i
];

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

/** git 命令是否携带外部执行路径 flag（-c 注入 / ext-diff / textconv / pager）。 */
function gitUnsafeExtension(normalized: string, program: string): ShellClassification | null {
  if (program !== 'git' && program !== 'git.exe') return null;
  if (GIT_UNSAFE_FLAGS.some((pattern) => pattern.test(normalized))) {
    return { level: 'medium', category: 'git-unsafe-extension', rule: 'git 外部执行路径（config 注入/pager/external diff/textconv）' };
  }
  return null;
}

/** 该命令是否执行项目代码（PROJECT_CODE_PROGRAMS 命中）。 */
function projectCodeExecution(normalized: string, program: string): ShellClassification | null {
  const entry = PROJECT_CODE_PROGRAMS[program];
  if (!entry) return null;
  const tokens = normalized.split(' ').map(unquote);
  const args = tokens.slice(1).map((token) => token.toLowerCase());
  if (args.length === 0) {
    // `make`/`pytest` 无参数同样是执行（默认目标/默认发现）。
    return { level: 'medium', category: 'project-code-execution', rule: `project code execution: ${program}` };
  }
  if (entry === '*') {
    return { level: 'medium', category: 'project-code-execution', rule: `project code execution: ${program}` };
  }
  // 版本 flag 不算执行（node --version / cmake --version 已在 allowlist 放行，
  // 这里兜底 npm ls 等受控子命令之外的情况）。
  const first = args[0] ?? '';
  if (entry.includes(first)) {
    return { level: 'medium', category: 'project-code-execution', rule: `project code execution: ${program} ${first}` };
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
  { category: 'security-software', rule: '安全软件/执行策略变更', pattern: /((set|add|remove)-mppreference\b|set-executionpolicy\b|mpcmdrun(\.exe)?\s+-(remove|disable|restore)|(^|[\s;|&])(wdac|applocker)\s+(policy|csp))/i },

  // ---- high
  { category: 'system-mutate', rule: '注册表写入', pattern: /(^|[\s;|&])(reg(\.exe)?\s+(add|delete|import|restore)|regedit\s+\/s|\bset-itemproperty\b[^|;&]{0,80}(hklm|hkcu|hkcr):|\bnew-itemproperty\b[^|;&]{0,80}(hklm|hkcu):)/i },
  { category: 'system-mutate', rule: '系统服务/驱动变更', pattern: /(^|[\s;|&])(sc(\.exe)?\s+(config|create|delete|stop|start)|\bnew-service\b|\bremove-service\b|(^|[\s;|&])net\s+(start|stop)\s|systemctl\s+(disable|enable|mask|stop|restart)|bcdedit|bootrec)/i },
  { category: 'system-mutate', rule: '系统组件变更', pattern: /(^|[\s;|&])(sfc\s|dism\s|wsl\s+(--unregister|--install)|netsh\s+(advfirewall|winhttp)\s+(set|reset))/i },
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
 * 分类一条命令。先扫危险模式，再查 git 外部扩展、项目代码执行与 allowlist；
 * 其余按 medium 处理（level 2 放行普通开发命令，level 1 拒绝）。
 */
export function classifyShellCommand(command: string, options: ClassifyOptions = {}): ShellClassification {
  const normalized = normalize(command);
  if (normalized === '') return { level: 'low', category: 'normal', rule: 'empty command' };
  for (const { category, rule, pattern } of DANGER_PATTERNS) {
    if (pattern.test(normalized)) return { level: CATEGORY_LEVEL[category]!, category, rule };
  }
  const program = programOf(normalized);
  const gitExtension = gitUnsafeExtension(normalized, program);
  if (gitExtension) return gitExtension;
  const allowlisted = isAllowlisted(normalized, program, options.userAllowlist ?? []);
  if (allowlisted) return allowlisted;
  const projectCode = projectCodeExecution(normalized, program);
  if (projectCode) return projectCode;
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
    return `SHELL_LEVEL_TOO_LOW: shell level 1 allows only read-only commands (file reads, read-only git queries, version checks). "${classification.rule}" needs a higher shell level; ask the user to raise it in Settings.`;
  }
  return `SHELL_LEVEL_TOO_LOW: this command is classified ${classification.level} (${classification.rule}); shell level 2 permits only ordinary development commands. Ask the user to raise the shell level in Settings if this command is genuinely intended.`;
}
