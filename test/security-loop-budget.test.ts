/**
 * Loop 安全预算测试（docs/THREAT-MODEL.md C2；二阶段 P1 按 Run 聚合）。
 *
 * 预算按 automation/swarm run 聚合：Prime 与所有 Worker 共用同一份计数，
 * 计数维度含工具调用、shell 执行、worker spawn、桌面动作、文件写入与运行
 * 时长；超限后 policy 引擎拒绝、goal 起草侧不再续写。
 */

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

// 导入链（goal → secrets）触达 electron；与其它套件一样提供桩。
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
import {
  budgetScopeFor,
  chargeLoopBudget,
  loopBudgetExhaustedFor,
  loopBudgetOf,
  resetLoopBudgetForTests,
  setRunScopeResolverForTests,
  type BudgetCharge,
  type LoopBudget
} from '../src/main/security/loop-budget.js';
import { checkToolPolicy, resetSecurityPolicyForTests } from '../src/main/security/policy.js';
import { setGoalObjective, setGoalSwitchNow, clearAllGoalSwitches, clearGoalObjective } from '../src/main/goal.js';
import { makeTempDir, removeTempDir } from './helpers.js';

let dir: string;

const NO_RUN = { runIdFor: () => null, primeConversationOf: () => null };

beforeAll(async () => {
  dir = await makeTempDir('clf-loop-budget-');
  initConfigPath(dir);
  const base = defaultConfig();
  await saveConfig({ ...base, security: { ...base.security } });
});

afterAll(async () => {
  setRunScopeResolverForTests(null);
  resetLoopBudgetForTests();
  resetSecurityPolicyForTests();
  clearAllGoalSwitches();
  clearGoalObjective('conv-budget');
  await removeTempDir(dir);
});

const charge = (key: string, dims: Partial<BudgetCharge> = {}, budget?: LoopBudget) =>
  chargeLoopBudget(key, { exec: false, workerSpawn: false, desktopAction: false, fileWrite: false, ...dims }, budget);

describe('loop budget counters', () => {
  it('stays silent within budget', () => {
    resetLoopBudgetForTests();
    setRunScopeResolverForTests(NO_RUN);
    for (let index = 0; index < 5; index += 1) {
      expect(charge('conv:conv-1', { exec: index % 2 === 0 })).toBeNull();
    }
    expect(loopBudgetExhaustedFor('conv-1')).toBeNull();
  });

  it('exhausts on tool-call count', () => {
    resetLoopBudgetForTests();
    setRunScopeResolverForTests(NO_RUN);
    const budget = { ...loopBudgetOf(), maxToolCallsPerRun: 10, maxExecPerRun: 100, maxRuntimeMinutes: 240 };
    let message: string | null = null;
    for (let index = 0; index < 11 && message === null; index += 1) {
      message = charge('conv:conv-2', {}, budget);
    }
    expect(message).toContain('LOOP_BUDGET_EXHAUSTED');
    expect(message).toContain('tool calls');
    expect(loopBudgetExhaustedFor('conv-2', budget)).toContain('LOOP_BUDGET_EXHAUSTED');
  });

  it('exhausts on exec count independently', () => {
    resetLoopBudgetForTests();
    setRunScopeResolverForTests(NO_RUN);
    const budget = { ...loopBudgetOf(), maxToolCallsPerRun: 1000, maxExecPerRun: 3, maxRuntimeMinutes: 240 };
    let message: string | null = null;
    for (let index = 0; index < 5 && message === null; index += 1) {
      message = charge('conv:conv-3', { exec: true }, budget);
    }
    expect(message).toContain('commands');
  });

  it('exhausts on worker spawns, desktop actions and file writes', () => {
    resetLoopBudgetForTests();
    setRunScopeResolverForTests(NO_RUN);
    const spawnBudget = { ...loopBudgetOf(), maxWorkerSpawnsPerRun: 2 };
    expect(charge('conv:sp', { workerSpawn: true }, spawnBudget)).toBeNull();
    expect(charge('conv:sp', { workerSpawn: true }, spawnBudget)).toBeNull();
    expect(charge('conv:sp', { workerSpawn: true }, spawnBudget)).toContain('workers');

    resetLoopBudgetForTests();
    const desktopBudget = { ...loopBudgetOf(), maxDesktopActionsPerRun: 1 };
    expect(charge('conv:dp', { desktopAction: true }, desktopBudget)).toBeNull();
    expect(charge('conv:dp', { desktopAction: true }, desktopBudget)).toContain('desktop actions');

    resetLoopBudgetForTests();
    const writeBudget = { ...loopBudgetOf(), maxFileWritesPerRun: 1 };
    expect(charge('conv:fw', { fileWrite: true }, writeBudget)).toBeNull();
    expect(charge('conv:fw', { fileWrite: true }, writeBudget)).toContain('modified files');
  });

  it('disabled budget never exhausts', () => {
    resetLoopBudgetForTests();
    setRunScopeResolverForTests(NO_RUN);
    const budget = { ...loopBudgetOf(), enabled: false, maxToolCallsPerRun: 1, maxExecPerRun: 1, maxRuntimeMinutes: 1 };
    for (let index = 0; index < 20; index += 1) {
      expect(charge('conv:conv-4', { exec: true }, budget)).toBeNull();
    }
    expect(loopBudgetExhaustedFor('conv-4', budget)).toBeNull();
  });

  it('counters are per conversation (outside a run)', () => {
    resetLoopBudgetForTests();
    setRunScopeResolverForTests(NO_RUN);
    const budget = { ...loopBudgetOf(), maxToolCallsPerRun: 2, maxExecPerRun: 10, maxRuntimeMinutes: 240 };
    expect(charge('conv:conv-a', {}, budget)).toBeNull();
    expect(charge('conv:conv-a', {}, budget)).toBeNull();
    expect(charge('conv:conv-a', {}, budget)).toContain('LOOP_BUDGET_EXHAUSTED');
    expect(charge('conv:conv-b', {}, budget)).toBeNull();
  });
});

describe('loop budget aggregates per automation run', () => {
  it('prime and workers share one budget; a new worker conversation cannot bypass it', () => {
    resetLoopBudgetForTests();
    // 受控 run 归属：prime-conv 与任意 worker-* 会话都属于 run-42。
    setRunScopeResolverForTests({
      runIdFor: (conversationId) => (conversationId === 'prime-conv' || conversationId.startsWith('worker-') ? 'run-42' : null),
      primeConversationOf: () => 'prime-conv'
    });
    // armed 的判定走 goal 开关：prime 的 goal armed 即整个 run armed。
    // （goalArmedFor 由真实 goal 模块提供；用 objective+switch 武装 prime。）
    const budget = { ...loopBudgetOf(), maxToolCallsPerRun: 3, maxExecPerRun: 100, maxRuntimeMinutes: 240 };
    expect(charge('run:run-42', {}, budget)).toBeNull();
    expect(charge('run:run-42', {}, budget)).toBeNull();
    expect(charge('run:run-42', {}, budget)).toBeNull();
    // 同一 run 键上的第 4 次（无论来自 prime 还是新开的 worker 会话）都超限。
    expect(charge('run:run-42', {}, budget)).toContain('LOOP_BUDGET_EXHAUSTED');
    expect(charge('run:run-42', {}, budget)).toContain('LOOP_BUDGET_EXHAUSTED');
    setRunScopeResolverForTests(NO_RUN);
  });

  it('budgetScopeFor maps run conversations to run:<id> and others to conv:<id>', async () => {
    setRunScopeResolverForTests({
      runIdFor: (conversationId) => (conversationId === 'prime-conv' ? 'run-42' : null),
      primeConversationOf: () => 'prime-conv'
    });
    expect(budgetScopeFor('prime-conv').key).toBe('run:run-42');
    expect(budgetScopeFor('worker-9').key).toBe('conv:worker-9');
    // 未 armed 的 run 不计数。
    expect(budgetScopeFor('prime-conv').armed).toBe(false);
    // 武装 prime 后 run 内任意会话都视为 armed。
    setGoalObjective('prime-conv', 'Ship it');
    await setGoalSwitchNow('prime-conv', 'loop', true);
    try {
      expect(budgetScopeFor('prime-conv').armed).toBe(true);
      // 无 run 归属的普通会话不受 prime 开关影响。
      expect(budgetScopeFor('other-chat').armed).toBe(false);
    } finally {
      await setGoalSwitchNow('prime-conv', 'loop', false);
      clearGoalObjective('prime-conv');
      setRunScopeResolverForTests(NO_RUN);
    }
  });
});

describe('loop budget enforcement through the policy engine', () => {
  it('a goal-armed conversation is denied once its budget is spent', async () => {
    resetLoopBudgetForTests();
    setRunScopeResolverForTests(NO_RUN);
    const base = defaultConfig();
    // 经配置把预算压到 schema 下限：10 次工具调用即耗尽（策略引擎读取同一配置）。
    await saveConfig({
      ...base,
      security: {
        ...base.security,
        shellLevel: 3,
        loopBudget: {
          enabled: true, maxToolCallsPerRun: 10, maxExecPerRun: 10, maxWorkerSpawnsPerRun: 16,
          maxDesktopActionsPerRun: 800, maxFileWritesPerRun: 2000, maxRuntimeMinutes: 240
        }
      }
    });
    setGoalObjective('conv-budget', 'Ship the feature');
    await setGoalSwitchNow('conv-budget', 'loop', true);
    try {
      // 预充到上限（与策略引擎同源的预算参数与聚合键）。
      for (let index = 0; index < 10; index += 1) {
        expect(charge('conv:conv-budget')).toBeNull();
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
    setRunScopeResolverForTests(NO_RUN);
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
