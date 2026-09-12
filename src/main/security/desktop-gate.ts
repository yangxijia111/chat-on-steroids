/**
 * 桌面控制目标防护（docs/THREAT-MODEL.md H1）。
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
 * 检查一次桌面动作是否允许作用于目标应用。
 *
 * @param action 动作类别：read（窗口枚举/状态）不受限；input（合成输入）、
 *   capture（截图）、launch（启动程序）受闸门约束。
 * @param appName 目标进程名；launch 时为待启动程序名/路径。
 * @param allowlist security.desktopAppAllowlist；空数组 = 不限制。
 */
export function checkDesktopTarget(
  action: DesktopAction,
  appName: string | null | undefined,
  allowlist: readonly string[]
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
    if (allowlist.length > 0 && normalized) {
      const allowed = allowlist.some((entry) => {
        const candidate = normalizeAppName(entry);
        return candidate !== null && (candidate === normalized || normalized.startsWith(candidate) || candidate.startsWith(normalized));
      });
      if (!allowed) {
        return {
          allowed: false,
          refusal:
            `DESKTOP_APP_NOT_ALLOWED: "${normalized}" is not on the desktop app allowlist configured for this app. ` +
            'Ask the user to add the application in Settings if desktop control of it is intended.'
        };
      }
    }
  }
  return { allowed: true, refusal: null };
}
