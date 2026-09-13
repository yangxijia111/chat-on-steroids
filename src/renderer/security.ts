/**
 * Security 设置页（威胁模型二阶段 P1）：shell 分级、工作区信任、worker 权限、
 * 桌面白名单、自动化预算与审计开关的渲染/保存，以及三个预设档位。
 *
 * 保存走与其它设置相同的 saveSettings 三方合并链路；绘制带 previous 比较，
 * 不覆盖用户正在编辑的字段。
 */

import type { AppState, Config, SecuritySettings } from '../shared/types.js';
import type { SettingsPatch } from '../preload/index.js';

const $ = <T extends HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing element #${id}`);
  return element as T;
};

/** 三个预设档位（Safe / Development / Full Automation）。Development 是推荐默认。 */
const PRESETS: Record<string, SecuritySettings> = {
  safe: {
    shellLevel: 1,
    workspaceTrust: 'untrusted',
    shellAllowlist: [],
    workerPermissions: 'restricted',
    desktopAppAllowlist: [],
    loopBudget: {
      enabled: true, maxToolCallsPerRun: 200, maxExecPerRun: 50, maxWorkerSpawnsPerRun: 4,
      maxDesktopActionsPerRun: 200, maxFileWritesPerRun: 500, maxRuntimeMinutes: 60
    },
    auditLog: true
  },
  development: {
    shellLevel: 2,
    workspaceTrust: 'trusted',
    shellAllowlist: [],
    workerPermissions: 'restricted',
    desktopAppAllowlist: [],
    loopBudget: {
      enabled: true, maxToolCallsPerRun: 800, maxExecPerRun: 200, maxWorkerSpawnsPerRun: 16,
      maxDesktopActionsPerRun: 800, maxFileWritesPerRun: 2000, maxRuntimeMinutes: 240
    },
    auditLog: true
  },
  full: {
    shellLevel: 3,
    workspaceTrust: 'full',
    shellAllowlist: [],
    workerPermissions: 'inherit',
    desktopAppAllowlist: [],
    loopBudget: {
      enabled: true, maxToolCallsPerRun: 4000, maxExecPerRun: 1000, maxWorkerSpawnsPerRun: 64,
      maxDesktopActionsPerRun: 4000, maxFileWritesPerRun: 10000, maxRuntimeMinutes: 720
    },
    auditLog: true
  }
};

const clamp = (value: number, min: number, max: number): number => Math.min(max, Math.max(min, value));

function numberValue(id: string, min: number, max: number, fallback: number): number {
  const raw = Number($<HTMLInputElement>(id).value);
  return Number.isFinite(raw) ? clamp(Math.round(raw), min, max) : fallback;
}

function linesValue(id: string): string[] {
  return $<HTMLTextAreaElement>(id).value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .slice(0, 64);
}

/** 从控件读出一份完整 security 快照（SettingsPatch.security）。 */
export function securitySettingsPatch(): Config['security'] {
  return {
    shellLevel: clamp(Number($<HTMLSelectElement>('securityShellLevel').value), 0, 3) as SecuritySettings['shellLevel'],
    workspaceTrust: $<HTMLSelectElement>('securityWorkspaceTrust').value as SecuritySettings['workspaceTrust'],
    shellAllowlist: linesValue('securityShellAllowlist'),
    workerPermissions: $<HTMLSelectElement>('securityWorkerPermissions').value as SecuritySettings['workerPermissions'],
    desktopAppAllowlist: linesValue('securityDesktopAllowlist'),
    loopBudget: {
      enabled: $<HTMLInputElement>('securityBudgetEnabled').checked,
      maxToolCallsPerRun: numberValue('securityBudgetToolCalls', 10, 100_000, 800),
      maxExecPerRun: numberValue('securityBudgetExecs', 1, 10_000, 200),
      maxWorkerSpawnsPerRun: numberValue('securityBudgetSpawns', 0, 1_000, 16),
      maxDesktopActionsPerRun: numberValue('securityBudgetDesktop', 1, 100_000, 800),
      maxFileWritesPerRun: numberValue('securityBudgetWrites', 1, 100_000, 2000),
      maxRuntimeMinutes: numberValue('securityBudgetRuntime', 1, 10_080, 240)
    },
    auditLog: $<HTMLInputElement>('securityAuditLog').checked
  };
}

/**
 * 应用持久化状态而不擦掉用户正在编辑的值：仅当控件持有焦点且与上一个持久化值
 * 不同（脏字段）时跳过；空闲字段始终跟随持久化状态。与 main.ts 的同名守卫同义。
 */
function applyValue(control: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement, next: string, previous?: string): void {
  const dirty = document.activeElement === control && previous !== undefined && control.value !== previous;
  if (!dirty) control.value = next;
}

function applyChecked(control: HTMLInputElement, next: boolean, previous?: boolean): void {
  const dirty = document.activeElement === control && previous !== undefined && control.checked !== previous;
  if (!dirty) control.checked = next;
}

/** 把新的 AppState 画到 Security 控件（脏字段守卫，不抢用户正在编辑的值）。 */
export function applySecurityState(next: AppState, previous: AppState | null): void {
  // 局部构造的 AppState（测试/旧快照）可能没有 security 段：跳过绘制而不是
  // 让异常中断整个 apply 管线。
  if (!next.config?.security) return;
  const security = next.config.security;
  const before = previous?.config?.security;
  applyValue($<HTMLSelectElement>('securityShellLevel'), String(security.shellLevel), before && String(before.shellLevel));
  applyValue($<HTMLSelectElement>('securityWorkspaceTrust'), security.workspaceTrust, before?.workspaceTrust);
  applyValue($<HTMLTextAreaElement>('securityShellAllowlist'), security.shellAllowlist.join('\n'), before?.shellAllowlist.join('\n'));
  applyValue($<HTMLSelectElement>('securityWorkerPermissions'), security.workerPermissions, before?.workerPermissions);
  applyValue($<HTMLTextAreaElement>('securityDesktopAllowlist'), security.desktopAppAllowlist.join('\n'), before?.desktopAppAllowlist.join('\n'));
  applyChecked($<HTMLInputElement>('securityBudgetEnabled'), security.loopBudget.enabled, before?.loopBudget.enabled);
  applyValue($<HTMLInputElement>('securityBudgetToolCalls'), String(security.loopBudget.maxToolCallsPerRun), before && String(before.loopBudget.maxToolCallsPerRun));
  applyValue($<HTMLInputElement>('securityBudgetExecs'), String(security.loopBudget.maxExecPerRun), before && String(before.loopBudget.maxExecPerRun));
  applyValue($<HTMLInputElement>('securityBudgetSpawns'), String(security.loopBudget.maxWorkerSpawnsPerRun), before && String(before.loopBudget.maxWorkerSpawnsPerRun));
  applyValue($<HTMLInputElement>('securityBudgetDesktop'), String(security.loopBudget.maxDesktopActionsPerRun), before && String(before.loopBudget.maxDesktopActionsPerRun));
  applyValue($<HTMLInputElement>('securityBudgetWrites'), String(security.loopBudget.maxFileWritesPerRun), before && String(before.loopBudget.maxFileWritesPerRun));
  applyValue($<HTMLInputElement>('securityBudgetRuntime'), String(security.loopBudget.maxRuntimeMinutes), before && String(before.loopBudget.maxRuntimeMinutes));
  applyChecked($<HTMLInputElement>('securityAuditLog'), security.auditLog, before?.auditLog);
}

/**
 * 绑定事件。`save` 是 main.ts 的设置保存入口；preset 按钮先把整档值写进控件
 * 再触发同一次保存。
 */
export function initSecurity(save: () => Promise<void>): void {
  const immediate = () => void save();
  for (const id of [
    'securityShellLevel', 'securityWorkspaceTrust', 'securityWorkerPermissions',
    'securityBudgetEnabled', 'securityAuditLog', 'securityBudgetToolCalls',
    'securityBudgetExecs', 'securityBudgetSpawns', 'securityBudgetDesktop',
    'securityBudgetWrites', 'securityBudgetRuntime'
  ]) {
    $(id).addEventListener('change', immediate);
  }
  // 文本域在失焦时保存（change 事件语义）。
  $('securityShellAllowlist').addEventListener('change', immediate);
  $('securityDesktopAllowlist').addEventListener('change', immediate);

  const applyPreset = (preset: SecuritySettings): void => {
    $<HTMLSelectElement>('securityShellLevel').value = String(preset.shellLevel);
    $<HTMLSelectElement>('securityWorkspaceTrust').value = preset.workspaceTrust;
    $<HTMLSelectElement>('securityWorkerPermissions').value = preset.workerPermissions;
    $<HTMLInputElement>('securityBudgetEnabled').checked = preset.loopBudget.enabled;
    $<HTMLInputElement>('securityBudgetToolCalls').value = String(preset.loopBudget.maxToolCallsPerRun);
    $<HTMLInputElement>('securityBudgetExecs').value = String(preset.loopBudget.maxExecPerRun);
    $<HTMLInputElement>('securityBudgetSpawns').value = String(preset.loopBudget.maxWorkerSpawnsPerRun);
    $<HTMLInputElement>('securityBudgetDesktop').value = String(preset.loopBudget.maxDesktopActionsPerRun);
    $<HTMLInputElement>('securityBudgetWrites').value = String(preset.loopBudget.maxFileWritesPerRun);
    $<HTMLInputElement>('securityBudgetRuntime').value = String(preset.loopBudget.maxRuntimeMinutes);
    $<HTMLInputElement>('securityAuditLog').checked = preset.auditLog;
    immediate();
  };
  $('presetSafe').addEventListener('click', () => applyPreset(PRESETS.safe!));
  $('presetDevelopment').addEventListener('click', () => applyPreset(PRESETS.development!));
  $('presetFull').addEventListener('click', () => applyPreset(PRESETS.full!));
}

/** 供 main.ts 组装 SettingsPatch 时使用（保持与其它设置段相同的调用形态）。 */
export function securityPatchForSave(_previous: Config['security']): SettingsPatch['security'] {
  return securitySettingsPatch();
}
