/**
 * Goal/Loop 安全预算（docs/THREAT-MODEL.md C2）。
 *
 * Loop 模式设计上不会自行停止，加固前没有任何迭代/时长/执行上限。预算按
 * 「一次 armed 运行」计：goalArmedFor(conversation) 为真期间累计工具调用与
 * shell 执行，开关关闭即清零。两个执行点：
 *
 *   - security/policy.ts 在每次工具调用时计数并强制（超限拒绝）；
 *   - goal.ts 在起草下一条自动回复前做只读检查（超限不再起草）。
 */

import { getConfig } from '../config.js';
import { goalArmedFor } from '../goal.js';

export interface LoopBudget {
  enabled: boolean;
  maxToolCallsPerRun: number;
  maxExecPerRun: number;
  maxRuntimeMinutes: number;
}

export function loopBudgetOf(): LoopBudget {
  const configured = getConfig().security?.loopBudget;
  return {
    enabled: configured?.enabled ?? true,
    maxToolCallsPerRun: configured?.maxToolCallsPerRun ?? 800,
    maxExecPerRun: configured?.maxExecPerRun ?? 200,
    maxRuntimeMinutes: configured?.maxRuntimeMinutes ?? 240
  };
}

interface BudgetCounter {
  firstAt: number;
  toolCalls: number;
  execCalls: number;
}

const budgetCounters = new Map<string, BudgetCounter>();

/** 会话的 goal 开关关闭时清零对应预算（下一次 armed 重新计）。 */
export function retireBudgetIfIdle(conversationId: string | null): void {
  if (conversationId && !goalArmedFor(conversationId)) budgetCounters.delete(conversationId);
}

/**
 * 计入一次活动并返回超限消息；null = 预算内。
 * 预算关闭时不计数（保持原语义）。
 */
export function chargeLoopBudget(conversationId: string, isExec: boolean, budget: LoopBudget = loopBudgetOf()): string | null {
  if (!budget.enabled) return null;
  let counter = budgetCounters.get(conversationId);
  if (!counter) {
    counter = { firstAt: Date.now(), toolCalls: 0, execCalls: 0 };
    budgetCounters.set(conversationId, counter);
  }
  counter.toolCalls += 1;
  if (isExec) counter.execCalls += 1;
  const exhausted = budgetExcess(counter, budget);
  return exhausted;
}

/** 只读检查：预算是否已耗尽（不计数）。goal 起草侧使用。 */
export function loopBudgetExhaustedFor(conversationId: string, budget: LoopBudget = loopBudgetOf()): string | null {
  if (!budget.enabled) return null;
  const counter = budgetCounters.get(conversationId);
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
  if (runtimeMinutes > budget.maxRuntimeMinutes) {
    return `LOOP_BUDGET_EXHAUSTED: this automated run has been running for ${Math.round(runtimeMinutes)} minutes (limit ${budget.maxRuntimeMinutes}). Automatic execution stops here; summarize progress and wait for the user.`;
  }
  return null;
}

/** 测试复位。 */
export function resetLoopBudgetForTests(): void {
  budgetCounters.clear();
}
