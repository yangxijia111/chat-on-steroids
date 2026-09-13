/**
 * 桌面控制目标防护（docs/THREAT-MODEL.md H1；二阶段 P1 fail-closed）。
 *
 * 两道闸门，都在实际执行输入注入/截图/启动的代码层，而非提示词层：
 *
 * 1. 敏感应用硬拒绝（默认、不可经配置关闭）：密码管理器、系统登录/UAC、
 *    系统设置与安全中心。对这些窗口的自动控制与截图直接拒绝——像素级捕获
 *    密码管理器等同凭据泄露，合成输入等同代用户解锁。
 *
 * 2. 可选应用白名单（security.desktopAppAllowlist）：用户显式列出
 *    UnrealEditor.exe / Unity.exe / Blender.exe 等后，控制类动作只允许作用于
 *    列表内应用；列表为空表示不限制（保持原功能，不破坏既有用户）。
 *
 * 二阶段 fail-closed 规则：
 *   - 白名单匹配是精确的 executable basename / 完整路径比较（大小写与斜杠
 *     归一后字符串相等），不再做前缀或模糊匹配；
 *   - 配置了白名单后，input/capture/launch 无法确认目标应用（无 window id、
 *     解析失败、进程名缺失）一律拒绝，绝不因「不知道目标是谁」而放行。
 */

/** 敏感进程名（小写、不含路径；.exe 可选）。命中即拒绝控制与截图。 */
const SENSITIVE_APPS: readonly string[] = [
  // 密码管理器
  '1password', '1password.exe', 'bitwarden', 'bitwarden.exe', 'keepass', 'keepass.exe',
  'keepassxc', 'keepassxc.exe', 'lastpass', 'lastpass.exe', 'dashlane', 'dashlane.exe',
  'enpass', 'enpass.exe',
  // Windows 登录 / UAC / 凭据 UI
  'consent.exe', 'logonui.exe', 'credentialuibroker.exe', 'lockapp.exe', 'lockapphost.exe',
  // 系统设置与安全中心
  'systemsettings.exe', 'systemsettings', 'securityhealth.exe', 'securityhealthservice.exe',
  'windowssecurity.exe',
  // 凭据/密钥系统服务窗口
  'vaultapp.exe'
];

const SENSITIVE_SET = new Set(SENSITIVE_APPS);

export type DesktopAction = 'read' | 'input' | 'capture' | 'launch';

export interface DesktopTargetCheck {
  allowed: boolean;
  refusal: string | null;
}

/** 进程/应用名归一化：basename、小写。 */
export function normalizeAppName(appName: string | null | undefined): string | null {
  if (!appName) return null;
  const base = appName.replaceAll('\\', '/').split('/').pop() ?? '';
  const lower = base.trim().toLowerCase();
  return lower === '' ? null : lower;
}

/** 该目标是否属于敏感应用硬拒绝集合。 */
export function isSensitiveApp(appName: string | null | undefined): boolean {
  const normalized = normalizeAppName(appName);
  if (!normalized) return false;
  if (SENSITIVE_SET.has(normalized)) return true;
  // 不带扩展名的匹配（macOS 进程名无 .exe）。
  if (SENSITIVE_SET.has(`${normalized}.exe`)) return true;
  return false;
}

/**
 * 白名单条目与目标的精确匹配。
 *
 * 条目含路径分隔符 → 按完整可执行路径比较（与 targetPath 逐字符相等，仅做
 * 大小写与斜杠方向归一）；否则按 basename 比较。不做前缀、后缀或模糊匹配：
 * allowlist 写 `notepad` 不会匹配 `notepad.exe`，写全名才会。
 */
function allowlistMatches(entry: string, targetName: string | null, targetPath: string | null | undefined): boolean {
  const trimmed = entry.trim().toLowerCase().replaceAll('/', '\\');
  if (trimmed === '') return false;
  if (trimmed.includes('\\')) {
    if (!targetPath || targetPath.trim() === '') return false;
    return targetPath.trim().toLowerCase().replaceAll('/', '\\') === trimmed;
  }
  const name = normalizeAppName(entry);
  return name !== null && name === targetName;
}

/**
 * 检查一次桌面动作是否允许作用于目标应用。
 *
 * @param action 动作类别：read（窗口枚举/状态）不受限；input（合成输入）、
 *   capture（截图）、launch（启动程序）受闸门约束。
 * @param appName 目标进程名；launch 时为待启动程序名/路径。
 * @param allowlist security.desktopAppAllowlist；空数组 = 不限制。
 * @param appPath 目标完整可执行路径（可空）——路径型白名单条目的比较依据。
 */
export function checkDesktopTarget(
  action: DesktopAction,
  appName: string | null | undefined,
  allowlist: readonly string[],
  appPath?: string | null
): DesktopTargetCheck {
  if (action === 'read') return { allowed: true, refusal: null };
  const normalized = normalizeAppName(appName);
  if (normalized && isSensitiveApp(normalized)) {
    return {
      allowed: false,
      refusal:
        `DESKTOP_TARGET_DENIED: "${normalized}" is a sensitive application (password manager, ` +
        'sign-in/UAC, or system settings) and cannot be driven or captured by automated control. ' +
        'Ask the user to perform this step manually.'
    };
  }
  if (action === 'launch' || action === 'input' || action === 'capture') {
    if (allowlist.length > 0) {
      // fail-closed：配置了白名单就必须能确认目标，确认不了就拒绝。
      if (!normalized) {
        return {
          allowed: false,
          refusal:
            'DESKTOP_TARGET_UNKNOWN: a desktop app allowlist is configured, but the target application ' +
            'of this action could not be confirmed (missing or unresolved target). Automated control and ' +
            'capture are refused rather than acting on an unknown application.'
        };
      }
      const allowed = allowlist.some((entry) => allowlistMatches(entry, normalized, appPath ?? null));
      if (!allowed) {
        return {
          allowed: false,
          refusal:
            `DESKTOP_APP_NOT_ALLOWED: "${normalized}" is not on the desktop app allowlist configured for this app ` +
            '(exact executable basename or full path entries only; no prefix matching). ' +
            'Ask the user to add the application in Settings if desktop control of it is intended.'
        };
      }
    }
  }
  return { allowed: true, refusal: null };
}
