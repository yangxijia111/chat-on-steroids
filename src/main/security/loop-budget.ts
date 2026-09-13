/**
 * Goal/Loop 安全预算（docs/THREAT-MODEL.md C2；二阶段 P1 按 Run 聚合）。
 *
 * Loop 模式设计上不会自行停止，加固前没有任何迭代/时长/执行上限。预算按
 * 「一次 armed 运行」计，聚合维度是 automation/swarm run：
 *
 *   - 会话属于某个 swarm run 时，预算键是 run:<runId> —— Prime 与所有 Worker
 *     共用同一份计数，Worker 开新会话也绕不过 Prime 的自动化预算；
 *   - 无 run 的独立 Goal/Loop 会话按 conv:<conversationId> 计；
 *   - armed 判定同样按 run 聚合：prime 的 goal 开关 armed 期间，run 内任何
 *     会话的调用都计数。
 *
 * 计数维度：tool calls、shell executions、worker spawn、desktop actions、
 * files modified、runtime。两个执行点：
 *
 *   - security/policy.ts 在每次工具调用时计数并强制（超限拒绝）；
 *   - goal.ts 在起草下一条自动回复前做只读检查（超限不再起草）。
 */

import { getConfig } from '../config.js';
import { currentRunId, primeConversation } from '../agents.js';
import { goalArmedFor } from '../goal.js';

export interface LoopBudget {
  enabled: boolean;
  maxToolCallsPerRun: number;
  maxExecPerRun: number;
  maxWorkerSpawnsPerRun: number;
  maxDesktopActionsPerRun: number;
  maxFileWritesPerRun: number;
  maxRuntimeMinutes: number;
}

export function loopBudgetOf(): LoopBudget {
  const configured = getConfig().security?.loopBudget;
  return {
    enabled: configured?.enabled ?? true,
    maxToolCallsPerRun: configured?.maxToolCallsPerRun ?? 800,
    maxExecPerRun: configured?.maxExecPerRun ?? 200,
    maxWorkerSpawnsPerRun: configured?.maxWorkerSpawnsPerRun ?? 16,
    maxDesktopActionsPerRun: configured?.maxDesktopActionsPerRun ?? 800,
    maxFileWritesPerRun: configured?.maxFileWritesPerRun ?? 2000,
    maxRuntimeMinutes: configured?.maxRuntimeMinutes ?? 240
  };
}

/** 一次调用计入的维度。 */
export interface BudgetCharge {
  exec: boolean;
  workerSpawn: boolean;
  desktopAction: boolean;
  fileWrite: boolean;
}

export interface BudgetScope {
  /** 聚合键：run:<runId>（swarm）或 conv:<conversationId>（独立 loop 会话）。 */
  key: string;
  /** 该范围内是否有 armed 的自动化（goal 开关）。 */
  armed: boolean;
}

/** run 归属查询（可注入，生产实现来自 agents.ts；测试用受控实现）。 */
export interface RunScopeResolver {
  runIdFor(conversationId: string): string | null;
  primeConversationOf(runId: string): string | null;
}

let runScopeResolver: RunScopeResolver = {
  runIdFor(conversationId) {
    try {
      return currentRunId(conversationId);
    } catch {
      return null;
    }
  },
  primeConversationOf(runId) {
    try {
      return primeConversation(runId);
    } catch {
      return null;
    }
  }
};

/** 测试注入受控的 run 归属实现。 */
export function setRunScopeResolverForTests(resolver: RunScopeResolver | null): void {
  runScopeResolver =
    resolver ??
    {
      runIdFor(conversationId) {
        try {
          return currentRunId(conversationId);
        } catch {
          return null;
        }
      },
      primeConversationOf(runId) {
        try {
          return primeConversation(runId);
        } catch {
          return null;
        }
      }
    };
}

/**
 * 解析一次调用的预算归属：run 级聚合优先，独立会话按会话计。
 * armed 的判定包含 run 的 prime 会话 —— worker 会话自身没有 goal 开关，
 * 但 prime armed 的 run 内调用同样消耗预算（防新会话绕过）。
 */
export function budgetScopeFor(conversationId: string | null): BudgetScope {
  if (!conversationId) return { key: 'anonymous', armed: false };
  const runId = runScopeResolver.runIdFor(conversationId);
  if (runId) {
    const prime = runScopeResolver.primeConversationOf(runId);
    return { key: `run:${runId}`, armed: (prime !== null && goalArmedFor(prime)) || goalArmedFor(conversationId) };
  }
  return { key: `conv:${conversationId}`, armed: goalArmedFor(conversationId) };
}

interface BudgetCounter {
  firstAt: number;
  toolCalls: number;
  execCalls: number;
  workerSpawns: number;
  desktopActions: number;
  fileWrites: number;
}

const budgetCounters = new Map<string, BudgetCounter>();

/** 该会话/运行不再 armed 时清零对应预算（下一次 armed 重新计）。 */
export function retireBudgetIfIdle(scopeKey: string | null): void {
  if (scopeKey && scopeKey !== 'anonymous') budgetCounters.delete(scopeKey);
}

/**
 * 计入一次活动并返回超限消息；null = 预算内。
 * 预算关闭时不计数（保持原语义）。
 */
export function chargeLoopBudget(
  scopeKey: string,
  charge: BudgetCharge,
  budget: LoopBudget = loopBudgetOf()
): string | null {
  if (!budget.enabled) return null;
  let counter = budgetCounters.get(scopeKey);
  if (!counter) {
    counter = { firstAt: Date.now(), toolCalls: 0, execCalls: 0, workerSpawns: 0, desktopActions: 0, fileWrites: 0 };
    budgetCounters.set(scopeKey, counter);
  }
  counter.toolCalls += 1;
  if (charge.exec) counter.execCalls += 1;
  if (charge.workerSpawn) counter.workerSpawns += 1;
  if (charge.desktopAction) counter.desktopActions += 1;
  if (charge.fileWrite) counter.fileWrites += 1;
  return budgetExcess(counter, budget);
}

/** 只读检查：预算是否已耗尽（不计数）。goal 起草侧使用。 */
export function loopBudgetExhaustedFor(conversationId: string, budget: LoopBudget = loopBudgetOf()): string | null {
  if (!budget.enabled) return null;
  const counter = budgetCounters.get(budgetScopeFor(conversationId).key);
  if (!counter) return null;
  return budgetExcess(counter, budget);
}

function budgetExcess(counter: BudgetCounter, budget: LoopBudget): string | null {
  const runtimeMinutes = (Date.now() - counter.firstAt) / 60_000;
  if (counter.toolCalls > budget.maxToolCallsPerRun) {
    return `LOOP_BUDGET_EXHAUSTED: this automated run has made ${counter.toolCalls} tool calls (limit ${budget.maxToolCallsPerRun}). Automatic execution stops here; summarize progress and wait for the user.`;
  }
  if (counter.execCalls > budget.maxExecPerRun) {
    return `LOOP_BUDGET_EXHAUSTED: this automated run has executed ${counter.execCalls} commands (limit ${budget.maxExecPerRun}). Automatic execution stops here; summarize progress and wait for the user.`;
  }
  if (counter.workerSpawns > budget.maxWorkerSpawnsPerRun) {
    return `LOOP_BUDGET_EXHAUSTED: this automated run has spawned ${counter.workerSpawns} workers (limit ${budget.maxWorkerSpawnsPerRun}). Automatic execution stops here; summarize progress and wait for the user.`;
  }
  if (counter.desktopActions > budget.maxDesktopActionsPerRun) {
    return `LOOP_BUDGET_EXHAUSTED: this automated run has performed ${counter.desktopActions} desktop actions (limit ${budget.maxDesktopActionsPerRun}). Automatic execution stops here; summarize progress and wait for the user.`;
  }
  if (counter.fileWrites > budget.maxFileWritesPerRun) {
    return `LOOP_BUDGET_EXHAUSTED: this automated run has modified files ${counter.fileWrites} times (limit ${budget.maxFileWritesPerRun}). Automatic execution stops here; summarize progress and wait for the user.`;
  }
  if (runtimeMinutes > budget.maxRuntimeMinutes) {
    return `LOOP_BUDGET_EXHAUSTED: this automated run has been running for ${Math.round(runtimeMinutes)} minutes (limit ${budget.maxRuntimeMinutes}). Automatic execution stops here; summarize progress and wait for the user.`;
  }
  return null;
}

/** 测试复位。 */
export function resetLoopBudgetForTests(): void {
  budgetCounters.clear();
}
