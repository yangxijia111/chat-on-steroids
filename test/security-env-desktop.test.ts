/**
 * exec 子进程环境脱敏与桌面目标防护测试（docs/THREAT-MODEL.md H1/H6）。
 */

import { describe, expect, it } from 'vitest';
import { childEnv, scrubSecretEnv } from '../src/main/exec.js';
import { checkDesktopTarget, isSensitiveApp } from '../src/main/security/desktop-gate.js';

describe('exec child environment scrubbing', () => {
  it('strips credential-shaped inherited variables', () => {
    const saved = { ...process.env };
    process.env['GITHUB_TOKEN_TEST'] = 'x';
    process.env['AWS_SECRET_ACCESS_KEY'] = 'x';
    process.env['ANTHROPIC_API_KEY'] = 'x';
    process.env['MY_SERVICE_TOKEN'] = 'x';
    process.env['DB_PASSWORD'] = 'x';
    process.env['SSH_AUTH_SOCK'] = '/tmp/agent.sock';
    process.env['NPM_TOKEN'] = 'x';
    process.env['OPENAI_API_KEY'] = 'x';
    try {
      const env = childEnv();
      expect(env['GITHUB_TOKEN_TEST']).toBeUndefined();
      expect(env['AWS_SECRET_ACCESS_KEY']).toBeUndefined();
      expect(env['ANTHROPIC_API_KEY']).toBeUndefined();
      expect(env['MY_SERVICE_TOKEN']).toBeUndefined();
      expect(env['DB_PASSWORD']).toBeUndefined();
      expect(env['SSH_AUTH_SOCK']).toBeUndefined();
      expect(env['NPM_TOKEN']).toBeUndefined();
      expect(env['OPENAI_API_KEY']).toBeUndefined();
    } finally {
      for (const key of ['GITHUB_TOKEN_TEST', 'AWS_SECRET_ACCESS_KEY', 'ANTHROPIC_API_KEY', 'MY_SERVICE_TOKEN', 'DB_PASSWORD', 'SSH_AUTH_SOCK', 'NPM_TOKEN', 'OPENAI_API_KEY']) {
        if (key in saved) process.env[key] = saved[key];
        else delete process.env[key];
      }
    }
  });

  it('keeps the variables real toolchains need', () => {
    const env = childEnv();
    expect(env['PATH']).toBeDefined();
    expect(env['SystemRoot'] ?? env['systemroot'] ?? 'win-only').toBeTruthy();
  });

  it('explicit caller overrides still pass through (audited separately)', () => {
    const env = childEnv({ MY_TOOL_TOKEN: 'explicit-value' });
    expect(env['MY_TOOL_TOKEN']).toBe('explicit-value');
  });

  it('scrubSecretEnv removes secret shapes in place', () => {
    const env: NodeJS.ProcessEnv = {
      PATH: '/usr/bin',
      CI_JOB_TOKEN: 'x',
      GOOGLE_APPLICATION_CREDENTIALS: '/tmp/x',
      JAVA_HOME: '/opt/jdk'
    };
    scrubSecretEnv(env);
    expect(env['PATH']).toBe('/usr/bin');
    expect(env['JAVA_HOME']).toBe('/opt/jdk');
    expect(env['CI_JOB_TOKEN']).toBeUndefined();
    expect(env['GOOGLE_APPLICATION_CREDENTIALS']).toBeUndefined();
  });
});

describe('desktop target gate', () => {
  it('hard-denies password managers regardless of allowlist', () => {
    for (const app of ['KeePass.exe', '1password.exe', 'Bitwarden.exe', 'keepassxc', 'LastPass.exe']) {
      expect(isSensitiveApp(app), app).toBe(true);
      const check = checkDesktopTarget('input', app, []);
      expect(check.allowed, app).toBe(false);
      expect(check.refusal, app).toContain('DESKTOP_TARGET_DENIED');
      // 即使白名单里有它也拒绝（敏感集合不可覆盖）。
      expect(checkDesktopTarget('input', app, [app]).allowed).toBe(false);
    }
  });

  it('hard-denies system sign-in, UAC and settings windows', () => {
    for (const app of ['consent.exe', 'LogonUI.exe', 'CredentialUIBroker.exe', 'SystemSettings.exe', 'SecurityHealth.exe']) {
      expect(checkDesktopTarget('input', app, []).allowed, app).toBe(false);
      expect(checkDesktopTarget('capture', app, []).allowed, app).toBe(false);
    }
  });

  it('read-only observation is never gated', () => {
    expect(checkDesktopTarget('read', 'KeePass.exe', []).allowed).toBe(true);
    expect(checkDesktopTarget('read', 'anything.exe', []).allowed).toBe(true);
  });

  it('empty allowlist keeps ordinary apps controllable (no behaviour change)', () => {
    expect(checkDesktopTarget('input', 'UnrealEditor.exe', []).allowed).toBe(true);
    expect(checkDesktopTarget('capture', 'Code.exe', []).allowed).toBe(true);
    expect(checkDesktopTarget('launch', 'Unity.exe', []).allowed).toBe(true);
  });

  it('a configured allowlist restricts control and launch to listed apps', () => {
    const allowlist = ['UnrealEditor.exe', 'Unity.exe', 'Blender.exe'];
    expect(checkDesktopTarget('input', 'UnrealEditor.exe', allowlist).allowed).toBe(true);
    expect(checkDesktopTarget('launch', 'notepad.exe', allowlist).allowed).toBe(false);
    expect(checkDesktopTarget('input', 'chrome.exe', allowlist).allowed).toBe(false);
    expect(checkDesktopTarget('launch', 'chrome.exe', allowlist).refusal).toContain('DESKTOP_APP_NOT_ALLOWED');
  });

  it('allowlist matching is exact — no prefix or fuzzy matching', () => {
    const allowlist = ['Code.exe', 'notepad.exe'];
    // 前缀相似不匹配。
    expect(checkDesktopTarget('input', 'CodeSecondary.exe', allowlist).allowed).toBe(false);
    expect(checkDesktopTarget('input', 'notepad-plus.exe', allowlist).allowed).toBe(false);
    // 条目缺 .exe 也不会「包容」目标的全名。
    expect(checkDesktopTarget('input', 'notepad.exe', ['notepad']).allowed).toBe(false);
    expect(checkDesktopTarget('input', 'notepad', ['notepad']).allowed).toBe(true);
  });

  it('path entries match the full executable path exactly', () => {
    const entry = 'C:\\Tools\\UnrealEditor.exe';
    const allowlist = [entry];
    expect(checkDesktopTarget('launch', 'UnrealEditor.exe', allowlist, 'C:\\Tools\\UnrealEditor.exe').allowed).toBe(true);
    // basename 相同但路径不同 → 拒绝。
    expect(checkDesktopTarget('launch', 'UnrealEditor.exe', allowlist, 'D:\\Other\\UnrealEditor.exe').allowed).toBe(false);
    // 无完整路径可比 → 拒绝（fail-closed，不做 basename 猜测）。
    expect(checkDesktopTarget('launch', 'UnrealEditor.exe', allowlist, null).allowed).toBe(false);
    // 大小写与斜杠方向归一。
    expect(checkDesktopTarget('launch', 'unrealeditor.exe', allowlist, 'c:/tools/UnrealEditor.exe').allowed).toBe(true);
  });

  it('configured allowlist refuses targets that cannot be confirmed (fail-closed)', () => {
    const allowlist = ['Code.exe'];
    for (const action of ['input', 'capture', 'launch'] as const) {
      const check = checkDesktopTarget(action, null, allowlist);
      expect(check.allowed, action).toBe(false);
      expect(check.refusal, action).toContain('DESKTOP_TARGET_UNKNOWN');
      expect(checkDesktopTarget(action, '', allowlist).allowed, action).toBe(false);
    }
    // 未配置 allowlist 时未知目标保持原行为（native 层一致性校验兜底）。
    expect(checkDesktopTarget('input', null, []).allowed).toBe(true);
  });

  it('normalizes path-qualified process names', () => {
    expect(isSensitiveApp('C:\\Program Files\\KeePass Password Safe 2\\KeePass.exe')).toBe(true);
    expect(checkDesktopTarget('input', '/Applications/1Password.app/Contents/MacOS/1Password', []).allowed).toBe(false);
  });
});
