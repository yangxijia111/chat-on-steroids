/**
 * Loop 安全预算测试（docs/THREAT-MODEL.md C2）。
 *
 * 预算按 armed 会话计数：工具调用、shell 执行与运行时长，超限后
 * policy 引擎拒绝、goal 起草侧不再续写。
 */

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

// 导入链（goal → secrets）触达 electron；与其它套件一样提供桩。
vi.mock('electron', () => ({
  safeStorage: {
    isAsyncEncryptionAvailable: vi.fn(async () => true),
    getSelectedStorageBackend: vi.fn(() => 'unknown'),
    encryptStringAsync: vi.fn(async (value: string) => Buffer.from(value, 'utf8')),
    decryptStringAsync: vi.fn(async (buffer: Buffer) => ({ result: buffer.toString('utf8'), shouldReEncrypt: false }))
  },
  clipboard: {},
  shell: {}
}));

import { defaultConfig, initConfigPath, saveConfig } from '../src/main/config.js';
import { chargeLoopBudget, loopBudgetExhaustedFor, loopBudgetOf, resetLoopBudgetForTests } from '../src/main/security/loop-budget.js';
import { checkToolPolicy, resetSecurityPolicyForTests } from '../src/main/security/policy.js';
import { setGoalObjective, setGoalSwitchNow, clearAllGoalSwitches, clearGoalObjective } from '../src/main/goal.js';
import { makeTempDir, removeTempDir } from './helpers.js';

let dir: string;

beforeAll(async () => {
  dir = await makeTempDir('clf-loop-budget-');
  initConfigPath(dir);
  const base = defaultConfig();
  await saveConfig({ ...base, security: { ...base.security } });
});

afterAll(async () => {
  resetLoopBudgetForTests();
  resetSecurityPolicyForTests();
  clearAllGoalSwitches();
  clearGoalObjective('conv-budget');
  await removeTempDir(dir);
});

describe('loop budget counters', () => {
  it('stays silent within budget', () => {
    resetLoopBudgetForTests();
    for (let index = 0; index < 5; index += 1) {
      expect(chargeLoopBudget('conv-1', index % 2 === 0)).toBeNull();
    }
    expect(loopBudgetExhaustedFor('conv-1')).toBeNull();
  });

  it('exhausts on tool-call count', () => {
    resetLoopBudgetForTests();
    const budget = { ...loopBudgetOf(), maxToolCallsPerRun: 10, maxExecPerRun: 100, maxRuntimeMinutes: 240 };
    let message: string | null = null;
    for (let index = 0; index < 11 && message === null; index += 1) {
      message = chargeLoopBudget('conv-2', false, budget);
    }
    expect(message).toContain('LOOP_BUDGET_EXHAUSTED');
    expect(message).toContain('tool calls');
    expect(loopBudgetExhaustedFor('conv-2', budget)).toContain('LOOP_BUDGET_EXHAUSTED');
  });

  it('exhausts on exec count independently', () => {
    resetLoopBudgetForTests();
    const budget = { enabled: true, maxToolCallsPerRun: 1000, maxExecPerRun: 3, maxRuntimeMinutes: 240 };
    let message: string | null = null;
    for (let index = 0; index < 5 && message === null; index += 1) {
      message = chargeLoopBudget('conv-3', true, budget);
    }
    expect(message).toContain('commands');
  });

  it('disabled budget never exhausts', () => {
    resetLoopBudgetForTests();
    const budget = { enabled: false, maxToolCallsPerRun: 1, maxExecPerRun: 1, maxRuntimeMinutes: 1 };
    for (let index = 0; index < 20; index += 1) {
      expect(chargeLoopBudget('conv-4', true, budget)).toBeNull();
    }
    expect(loopBudgetExhaustedFor('conv-4', budget)).toBeNull();
  });

  it('counters are per conversation', () => {
    resetLoopBudgetForTests();
    const budget = { enabled: true, maxToolCallsPerRun: 2, maxExecPerRun: 10, maxRuntimeMinutes: 240 };
    expect(chargeLoopBudget('conv-a', false, budget)).toBeNull();
    expect(chargeLoopBudget('conv-a', false, budget)).toBeNull();
    expect(chargeLoopBudget('conv-a', false, budget)).toContain('LOOP_BUDGET_EXHAUSTED');
    expect(chargeLoopBudget('conv-b', false, budget)).toBeNull();
  });
});

describe('loop budget enforcement through the policy engine', () => {
  it('a goal-armed conversation is denied once its budget is spent', async () => {
    resetLoopBudgetForTests();
    const base = defaultConfig();
    // 经配置把预算压到 schema 下限：10 次工具调用即耗尽（策略引擎读取同一配置）。
    await saveConfig({
      ...base,
      security: { ...base.security, shellLevel: 3, loopBudget: { enabled: true, maxToolCallsPerRun: 10, maxExecPerRun: 10, maxRuntimeMinutes: 240 } }
    });
    setGoalObjective('conv-budget', 'Ship the feature');
    await setGoalSwitchNow('conv-budget', 'loop', true);
    try {
      // 预充到上限（与策略引擎同源的预算参数）。
      for (let index = 0; index < 10; index += 1) {
        expect(chargeLoopBudget('conv-budget', false)).toBeNull();
      }
      // 第 11 次调用（经策略引擎）应当被拒绝。
      const verdict = checkToolPolicy({
        tool: 'exec_command',
        args: { cmd: 'echo hello' },
        conversationId: 'conv-budget',
        sessionId: null,
        agent: null
      });
      expect(verdict.allowed).toBe(false);
      expect(verdict.refusal).toContain('LOOP_BUDGET_EXHAUSTED');
      // 起草侧的只读检查同样报耗尽。
      expect(loopBudgetExhaustedFor('conv-budget')).toContain('LOOP_BUDGET_EXHAUSTED');
    } finally {
      await setGoalSwitchNow('conv-budget', 'loop', false);
      await saveConfig({ ...defaultConfig(), security: { ...defaultConfig().security } });
    }
  });

  it('an idle (not goal-armed) conversation is never budget-gated', () => {
    resetLoopBudgetForTests();
    const verdict = checkToolPolicy({
      tool: 'exec_command',
      args: { cmd: 'echo hello' },
      conversationId: 'conv-plain',
      sessionId: null,
      agent: null
    });
    expect(verdict.allowed).toBe(true);
  });
});
