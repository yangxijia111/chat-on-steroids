/**
 * 工具安全描述符测试（威胁模型二阶段 P0：Plugin 纳入 Capability Policy）。
 *
 * 覆盖：核心 surface 工具全覆盖（未知即 fail-closed 的前提）、描述符字段
 * 一致性、restricted worker 对 plugin/未知工具默认拒绝、inherit 放行。
 */

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

vi.mock('electron', () => ({
  safeStorage: {
    isAsyncEncryptionAvailable: vi.fn(async () => true),
    getSelectedStorageBackend: vi.fn(() => 'unknown'),
    encryptStringAsync: vi.fn(async (value: string) => Buffer.from(value, 'utf8')),
    decryptStringAsync: vi.fn(async (buffer: Buffer) => ({ result: buffer.toString('utf8'), shouldReencrypt: false }))
  },
  clipboard: {},
  shell: {}
}));

import { defaultConfig, initConfigPath, saveConfig } from '../src/main/config.js';
import { checkToolPolicy, resetSecurityPolicyForTests } from '../src/main/security/policy.js';
import { descriptorFor, hasExplicitDescriptor, UNKNOWN_TOOL_DESCRIPTOR } from '../src/main/security/tool-descriptors.js';
import { SURFACES } from '../src/main/mcp/surfaces.js';
import { WINDOWS_COMPUTER_METHODS } from '../src/shared/windows-computer.js';
import { makeTempDir, removeTempDir } from './helpers.js';

let dir: string;

beforeAll(async () => {
  dir = await makeTempDir('clf-tool-descriptors-');
  initConfigPath(dir);
  await saveConfig({ ...defaultConfig(), security: { ...defaultConfig().security } });
});

afterAll(async () => {
  resetSecurityPolicyForTests();
  await removeTempDir(dir);
});

const call = (tool: string, args: unknown, extra: Partial<Parameters<typeof checkToolPolicy>[0]> = {}) =>
  checkToolPolicy({ tool, args, conversationId: null, sessionId: null, agent: null, surface: 'core', ...extra });

describe('tool descriptors: every core-surface tool has an explicit descriptor', () => {
  it('core and desktop tool lists are fully covered', () => {
    const coreTools = SURFACES.core.tools;
    const desktopTools = [...WINDOWS_COMPUTER_METHODS, 'read_clipboard', 'write_clipboard', 'observe', 'computer', 'exec'];
    for (const tool of [...coreTools, ...desktopTools]) {
      expect(hasExplicitDescriptor(tool), tool).toBe(true);
    }
  });

  it('unknown tool names fall back to the fail-closed descriptor', () => {
    const unknown = descriptorFor('totally-not-a-known-tool');
    expect(unknown).toBe(UNKNOWN_TOOL_DESCRIPTOR);
    expect(unknown.workerPolicy).toBe('deny');
    expect(unknown.risk).toBe('high');
    expect(unknown.processExecution).toBe(true);
  });
});

describe('tool descriptors: restricted workers cannot use plugin tools', () => {
  it('third-party plugin tool names are denied for restricted workers', () => {
    const worker = { agent: 'worker-1', surface: 'plugins' as const };
    expect(call('blender_get_scene_info', { user_prompt: 'x' }, worker).refusal).toContain('WORKER_PERMISSION_REQUIRED');
    expect(call('some_plugin_arbitrary_tool', {}, worker).refusal).toContain('WORKER_PERMISSION_REQUIRED');
  });

  it('plugin-reported readOnly annotations do not matter — the name is unknown either way', () => {
    // 插件自报 annotations 不是安全边界：描述符表之外一律按未知处理。
    const worker = { agent: 'worker-1', surface: 'plugins' as const };
    expect(call('plugin_claiming_readonly', {}, worker).allowed).toBe(false);
  });

  it('the prime chat keeps calling plugin tools (behaviour preserved)', () => {
    const prime = { agent: 'prime', surface: 'plugins' as const };
    expect(call('blender_get_scene_info', { user_prompt: 'x' }, prime).allowed).toBe(true);
  });

  it('inherit mode restores plugin access for workers', async () => {
    await saveConfig({
      ...defaultConfig(),
      security: { ...defaultConfig().security, workerPermissions: 'inherit' }
    });
    expect(call('blender_get_scene_info', { user_prompt: 'x' }, { agent: 'worker-1', surface: 'plugins' }).allowed).toBe(true);
    await saveConfig({ ...defaultConfig(), security: { ...defaultConfig().security } });
  });
});

describe('tool descriptors: read/coordination tools stay allowed for workers', () => {
  it('worker-allowed tools have workerPolicy allow', () => {
    for (const tool of ['read', 'view_image', 'find', 'session', 'update_plan', 'agents', 'session_finish']) {
      const verdict = call(tool, {}, { agent: 'worker-1' });
      expect(verdict.allowed, tool).toBe(true);
    }
  });
});
