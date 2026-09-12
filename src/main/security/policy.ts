/**
 * Capability 策略引擎 — 所有模型可见工具调用的统一安全决策层。
 *
 * docs/THREAT-MODEL.md 的核心结论：LLM → Tool → OS 链路上，唯一可靠的安全边界
 * 是执行工具的代码本身。本模块在 kernel.dispatch（每个工具调用的咽喉点）执行：
 *
 *   1. Shell 分级（security.shellLevel 0-3）：exec_command 逐条分类，
 *      write_stdin 对输入文本同样分类（防绕过，C4）；
 *   2. Worker 权限降级（security.workerPermissions）：restricted 模式下
 *      worker 会话只能读，不能写/执行/控制桌面（C3）；
 *   3. Goal/Loop 安全预算（security.loopBudget）：armed goal 期间按会话计数
 *      工具调用、shell 执行与运行时长，超限拒绝（C2）；
 *   4. 审计：所有拒绝 + 所有高风险放行写入 security/audit.jsonl（H7）。
 *
 * 模型不是安全边界：以上全部在实际执行代码中，与提示词无关。
 */

import { getConfig } from '../config.js';
import { agentInfoForOwnedConversation, PRIME_ID } from '../agents.js';
import { goalArmedFor } from '../goal.js';
import { classifyShellCommand, shellLevelAllows, shellLevelRefusal, type ShellClassification } from './shell-policy.js';
import { chargeLoopBudget, loopBudgetOf, retireBudgetIfIdle, resetLoopBudgetForTests } from './loop-budget.js';
import { recordSecurityAudit, type AuditDecision, type AuditRiskLevel } from './audit.js';
import type { Capability } from '../../shared/types.js';
import { WINDOWS_COMPUTER_READ_METHODS, WINDOWS_COMPUTER_INPUT_METHODS } from '../../shared/windows-computer.js';

export interface PolicyCheckContext {
  tool: string;
  args: unknown;
  conversationId: string | null;
  sessionId: string | null;
  agent: string | null;
}

export interface PolicyVerdict {
  allowed: boolean;
  refusal: string | null;
}

/** 工具 → 所需 capability（反向映射，供 worker 降级判断）。 */
const TOOL_CAPABILITY: ReadonlyMap<string, Capability> = (() => {
  const map = new Map<string, Capability>();
  map.set('read', 'read');
  map.set('view_image', 'read');
  map.set('find', 'search');
  map.set('apply_patch', 'edit');
  map.set('exec_command', 'command');
  map.set('write_stdin', 'command');
  map.set('download_artifact', 'saveArtifact');
  map.set('observe', 'screen');
  map.set('computer', 'control');
  for (const method of WINDOWS_COMPUTER_READ_METHODS) map.set(method, 'screen');
  for (const method of WINDOWS_COMPUTER_INPUT_METHODS) map.set(method, 'control');
  map.set('read_clipboard', 'clipboardRead');
  map.set('write_clipboard', 'clipboardWrite');
  return map;
})();

/** restricted 模式下 worker 禁止的 capability：一切写入、执行与桌面能力。 */
const WORKER_DENIED_CAPABILITIES: ReadonlySet<Capability> = new Set([
  'create', 'edit', 'move', 'deleteFile', 'command', 'saveArtifact',
  'screen', 'control', 'clipboardRead', 'clipboardWrite'
]);

// 说明：agents / session_finish / update_plan / session 等工具没有 capability 映射，
// 不在降级范围内 —— worker 必须能上报状态与协作，这些工具本身不触达文件/执行/桌面。

/** 这次调用是否来自 worker（会话归属为据，agent id 形态为辅）。 */
function isWorkerCall(context: PolicyCheckContext): boolean {
  const info = context.conversationId ? agentInfoForOwnedConversation(context.conversationId) : null;
  if (info) return info.role === 'worker';
  // 归属查不到时（dormant/边界）按 agent id 收敛：非 prime 的具名 agent 即 worker。
  return context.agent !== null && context.agent !== PRIME_ID;
}

// ------------------------------------------------------------------ loop budget
// 预算的计数与持久逻辑在 ./loop-budget.ts（goal.ts 起草侧也做只读检查）。

export { resetLoopBudgetForTests as resetSecurityPolicyForTests };

// ------------------------------------------------------------------ policy check

function extractCommandTexts(context: PolicyCheckContext): string[] {
  const args = context.args && typeof context.args === 'object' ? (context.args as Record<string, unknown>) : {};
  if (context.tool === 'exec_command') {
    const commands: string[] = [];
    if (typeof args['cmd'] === 'string') commands.push(args['cmd']);
    if (Array.isArray(args['cmds'])) {
      for (const entry of args['cmds']) if (typeof entry === 'string') commands.push(entry);
    }
    return commands;
  }
  if (context.tool === 'write_stdin' && typeof args['chars'] === 'string') return [args['chars']];
  return [];
}

/** write_stdin 的短输入（y/n/回车等对已放行命令的应答）在 level 1 直接放行。 */
const SHORT_STDIN_CHARS = 4;

function audit(
  context: PolicyCheckContext,
  action: string,
  target: string | null,
  risk: AuditRiskLevel | null,
  decision: AuditDecision,
  reason: string | null
): void {
  recordSecurityAudit({
    session: context.sessionId,
    agent: context.agent,
    tool: context.tool,
    action,
    target,
    risk,
    decision,
    reason
  });
}

/**
 * 策略总闸。返回 allowed=false 时 dispatch 以 refusal 文案拒绝，工具不执行。
 * 只读低风险路径不写审计，保持日志信噪比。
 */
export function checkToolPolicy(context: PolicyCheckContext): PolicyVerdict {
  const config = getConfig();
  const security = config.security;

  // ---- Goal/Loop 预算（armed 期间才计数；关闭即清零）
  if (context.conversationId && goalArmedFor(context.conversationId)) {
    const isExec = context.tool === 'exec_command' || context.tool === 'write_stdin';
    const exhausted = chargeLoopBudget(context.conversationId, isExec, loopBudgetOf());
    if (exhausted) {
      audit(context, isExec ? 'shell.execute' : 'tool.call', null, 'high', 'denied-budget', exhausted.slice(0, 160));
      return { allowed: false, refusal: exhausted };
    }
  } else {
    retireBudgetIfIdle(context.conversationId);
  }

  // ---- Worker 权限降级
  if (security?.workerPermissions === 'restricted' && isWorkerCall(context)) {
    const capability = TOOL_CAPABILITY.get(context.tool);
    if (capability !== undefined && WORKER_DENIED_CAPABILITIES.has(capability)) {
      audit(context, 'tool.call', context.tool, 'medium', 'denied-worker-permission', `worker needs ${capability}; workers run restricted by default`);
      return {
        allowed: false,
        refusal:
          `WORKER_PERMISSION_REQUIRED: worker agents run restricted by default and cannot use ${context.tool} ` +
          '(which needs a write/execute/desktop permission). Ask the user to grant workers broader permissions in Settings, ' +
          'or have the prime chat perform this step and hand the result back.'
      };
    }
  }

  // ---- Shell 分级
  if (context.tool === 'exec_command' || context.tool === 'write_stdin') {
    const shellLevel = security?.shellLevel ?? 2;
    const texts = extractCommandTexts(context);
    const userAllowlist = security?.shellAllowlist ?? [];
    let worst: ShellClassification | null = null;
    for (const text of texts) {
      // write_stdin 的极短应答（y/n/回车）无法也无需分类。
      if (context.tool === 'write_stdin' && text.trim().length <= SHORT_STDIN_CHARS) continue;
      const classification = classifyShellCommand(text, { userAllowlist });
      if (!worst || severity(classification.level) > severity(worst.level)) worst = classification;
    }
    if (worst) {
      const passes = shellLevelAllows(shellLevel, worst.level);
      if (!passes) {
        const refusal = shellLevelRefusal(shellLevel, worst);
        audit(context, 'shell.execute', texts[0] ?? null, worst.level, 'denied-shell-level', worst.rule);
        return { allowed: false, refusal };
      }
      if (worst.level === 'high' || worst.level === 'critical') {
        audit(context, 'shell.execute', texts[0] ?? null, worst.level, 'allowed-escalated', worst.rule);
      }
    }
  }

  return { allowed: true, refusal: null };
}

function severity(level: string): number {
  switch (level) {
    case 'critical': return 3;
    case 'high': return 2;
    case 'medium': return 1;
    default: return 0;
  }
}
