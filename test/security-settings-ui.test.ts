/**
 * Security 设置页测试（威胁模型二阶段 P1）：绘制、控件读取、预设档位与保存触发。
 * 沿用 context-meter 的 jsdom + index.html 模式。
 */

import { JSDOM } from 'jsdom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { applySecurityState, initSecurity, securitySettingsPatch } from '../src/renderer/security.js';
import type { AppState, SecuritySettings } from '../src/shared/types.js';

let dom: JSDOM | undefined;
afterEach(() => { dom?.window.close(); vi.unstubAllGlobals(); });

function setup(security: SecuritySettings, previous?: SecuritySettings): Document {
  dom = new JSDOM(readFileSync('src/renderer/index.html', 'utf8'));
  vi.stubGlobal('document', dom.window.document);
  const config = { security } as AppState['config'];
  const previousState = previous ? ({ config: { security: previous } } as AppState) : null;
  applySecurityState({ config } as AppState, previousState);
  return dom.window.document;
}

const DEVELOPMENT: SecuritySettings = {
  shellLevel: 2, workspaceTrust: 'trusted', shellAllowlist: [], workerPermissions: 'restricted',
  desktopAppAllowlist: [], loopBudget: {
    enabled: true, maxToolCallsPerRun: 800, maxExecPerRun: 200, maxWorkerSpawnsPerRun: 16,
    maxDesktopActionsPerRun: 800, maxFileWritesPerRun: 2000, maxRuntimeMinutes: 240
  },
  auditLog: true
};

describe('security settings ui', () => {
  it('paints every control from state', () => {
    const doc = setup(DEVELOPMENT);
    expect((doc.getElementById('securityShellLevel') as HTMLSelectElement).value).toBe('2');
    expect((doc.getElementById('securityWorkspaceTrust') as HTMLSelectElement).value).toBe('trusted');
    expect((doc.getElementById('securityWorkerPermissions') as HTMLSelectElement).value).toBe('restricted');
    expect((doc.getElementById('securityBudgetEnabled') as HTMLInputElement).checked).toBe(true);
    expect((doc.getElementById('securityBudgetExecs') as HTMLInputElement).value).toBe('200');
    expect((doc.getElementById('securityBudgetSpawns') as HTMLInputElement).value).toBe('16');
    expect((doc.getElementById('securityAuditLog') as HTMLInputElement).checked).toBe(true);
  });

  it('reads the controls back into a complete settings snapshot', () => {
    const doc = setup(DEVELOPMENT);
    (doc.getElementById('securityShellLevel') as HTMLSelectElement).value = '1';
    (doc.getElementById('securityWorkspaceTrust') as HTMLSelectElement).value = 'untrusted';
    (doc.getElementById('securityBudgetExecs') as HTMLInputElement).value = '50';
    (doc.getElementById('securityShellAllowlist') as HTMLTextAreaElement).value = 'RunUAT.bat\n\ngit status ';
    const patch = securitySettingsPatch();
    expect(patch.shellLevel).toBe(1);
    expect(patch.workspaceTrust).toBe('untrusted');
    expect(patch.shellAllowlist).toEqual(['RunUAT.bat', 'git status']);
    expect(patch.loopBudget.maxExecPerRun).toBe(50);
  });

  it('clamps out-of-range numbers to the schema bounds instead of refusing the save', () => {
    const doc = setup(DEVELOPMENT);
    (doc.getElementById('securityBudgetExecs') as HTMLInputElement).value = '999999';
    (doc.getElementById('securityBudgetRuntime') as HTMLInputElement).value = '0';
    const patch = securitySettingsPatch();
    expect(patch.loopBudget.maxExecPerRun).toBe(10_000);
    expect(patch.loopBudget.maxRuntimeMinutes).toBe(1);
  });

  it('presets write the full ladder into the controls and save once', () => {
    const doc = setup(DEVELOPMENT);
    const save = vi.fn(async () => undefined);
    initSecurity(save);
    (doc.getElementById('presetFull') as HTMLButtonElement).click();
    expect(save).toHaveBeenCalledTimes(1);
    const patch = securitySettingsPatch();
    expect(patch.shellLevel).toBe(3);
    expect(patch.workspaceTrust).toBe('full');
    expect(patch.workerPermissions).toBe('inherit');
    expect(patch.loopBudget.maxToolCallsPerRun).toBe(4000);
    // Safe 档位是最收紧的。
    (doc.getElementById('presetSafe') as HTMLButtonElement).click();
    const safe = securitySettingsPatch();
    expect(safe.shellLevel).toBe(1);
    expect(safe.workspaceTrust).toBe('untrusted');
    expect(safe.workerPermissions).toBe('restricted');
    expect(safe.loopBudget.maxToolCallsPerRun).toBe(200);
    // Development 是推荐默认。
    (doc.getElementById('presetDevelopment') as HTMLButtonElement).click();
    expect(securitySettingsPatch()).toEqual(DEVELOPMENT);
  });

  it('control changes go through the shared save entry point', () => {
    const doc = setup(DEVELOPMENT);
    const save = vi.fn(async () => undefined);
    initSecurity(save);
    const change = () => new dom!.window.Event('change');
    (doc.getElementById('securityShellLevel') as HTMLSelectElement).dispatchEvent(change());
    expect(save).toHaveBeenCalledTimes(1);
    (doc.getElementById('securityAuditLog') as HTMLInputElement).dispatchEvent(change());
    expect(save).toHaveBeenCalledTimes(2);
  });

  it('does not clobber a focused control the user is editing when state repaints', () => {
    const doc = setup(DEVELOPMENT);
    const select = doc.getElementById('securityShellLevel') as HTMLSelectElement;
    select.focus();
    select.value = '0';
    // 同值重绘（previous 与 next 相同）不得覆盖未保存的编辑。
    applySecurityState({ config: { security: DEVELOPMENT } } as AppState, { config: { security: DEVELOPMENT } } as AppState);
    expect(select.value).toBe('0');
    // 失焦后（非脏字段）跟随持久化状态。
    select.blur();
    applySecurityState({ config: { security: DEVELOPMENT } } as AppState, { config: { security: DEVELOPMENT } } as AppState);
    expect(select.value).toBe('2');
  });
});
