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
import { classifyShellCommand, shellLevelAllows, shellLevelRefusal, type ShellClassification } from './shell-policy.js';
import { chargeLoopBudget, loopBudgetOf, budgetScopeFor, retireBudgetIfIdle, resetLoopBudgetForTests } from './loop-budget.js';
import { recordSecurityAudit, type AuditDecision, type AuditRiskLevel } from './audit.js';
import { descriptorFor, hasExplicitDescriptor } from './tool-descriptors.js';

export interface PolicyCheckContext {
  tool: string;
  args: unknown;
  conversationId: string | null;
  sessionId: string | null;
  agent: string | null;
  /** 调用所在 surface（core/desktop/plugins）；plugin 工具名不在核心描述符表内。 */
  surface?: string | null;
}

export interface PolicyVerdict {
  allowed: boolean;
  refusal: string | null;
  /** 需要本地人工确认的 critical 动作（kernel.dispatch 异步解决后才放行）。 */
  pendingApproval?: import('./approval.js').CriticalApprovalRequest;
}

// 工具安全元数据统一在 ./tool-descriptors.ts（Core 与 Plugin 同一套）：
// capability 需求、风险、文件/网络/执行/桌面能力面与 worker 策略都在描述符里，
// 本文件只按描述符决策，不再维护「工具名 → capability」特判表。
//
// 说明：agents / session_finish / update_plan / session 等协作工具的描述符
// workerPolicy = allow —— worker 必须能上报状态与协作，这些工具不触达文件/
// 执行/桌面。第三方 plugin 工具名不在描述符表内，descriptorFor 对其返回
// fail-closed 的 UNKNOWN_TOOL_DESCRIPTOR（restricted worker 一律拒绝）。

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

  // ---- Goal/Loop 预算（按 automation/swarm run 聚合；armed 期间才计数；关闭即清零）
  const budgetScope = budgetScopeFor(context.conversationId);
  if (budgetScope.armed) {
    const descriptor = descriptorFor(context.tool);
    const isExec = context.tool === 'exec_command' || context.tool === 'write_stdin';
    const isSpawn = context.tool === 'agents' && (context.args as { action?: unknown } | null)?.['action'] === 'spawn';
    const exhausted = chargeLoopBudget(
      budgetScope.key,
      {
        exec: isExec,
        workerSpawn: isSpawn,
        desktopAction: descriptor.desktopControl === true,
        fileWrite: descriptor.filesystem === 'write'
      },
      loopBudgetOf()
    );
    if (exhausted) {
      audit(context, isExec ? 'shell.execute' : 'tool.call', null, 'high', 'denied-budget', exhausted.slice(0, 160));
      return { allowed: false, refusal: exhausted };
    }
  } else {
    retireBudgetIfIdle(budgetScope.key);
  }

  // ---- Worker 权限降级（按工具安全描述符，Core 与 Plugin 同一套）
  if (security?.workerPermissions === 'restricted' && isWorkerCall(context)) {
    const descriptor = descriptorFor(context.tool);
    if (descriptor.workerPolicy === 'deny') {
      const unknown = !hasExplicitDescriptor(context.tool);
      audit(
        context,
        'tool.call',
        context.tool,
        descriptor.risk,
        'denied-worker-permission',
        unknown
          ? 'plugin/unknown tool has no explicit security descriptor; workers run restricted by default'
          : `tool requires ${descriptor.capabilities.join(', ') || 'execute/write/desktop'} capability; workers run restricted by default`
      );
      return {
        allowed: false,
        refusal:
          `WORKER_PERMISSION_REQUIRED: worker agents run restricted by default and cannot use ${context.tool} ` +
          '(which needs a write/execute/desktop permission). Ask the user to grant workers broader permissions in Settings, ' +
          'or have the prime chat perform this step and hand the result back.'
      };
    }
  }

  // ---- Shell 分级 + 工作区信任
  if (context.tool === 'exec_command' || context.tool === 'write_stdin') {
    const shellLevel = security?.shellLevel ?? 2;
    const workspaceTrust = security?.workspaceTrust ?? 'trusted';
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
      // 执行项目代码（npm test、make、pytest、cargo build、Unreal/Unity build…）
      // 是独立于 shell 分级的信任闸：陌生仓库里的一次构建就是执行仓库作者留下的
      // 任意代码（postinstall、conftest、build.rs、自定义构建步骤）。
      if (worst.category === 'project-code-execution' && workspaceTrust === 'untrusted') {
        const refusal =
          'WORKSPACE_TRUST_REQUIRED: this command executes project code ' +
          `(${worst.rule}), and this workspace is marked untrusted. Building, testing or scripting an ` +
          'untrusted repository runs code its authors left in it. Ask the user to mark the workspace ' +
          'trusted in Settings (Security) if they have reviewed the repository.';
        audit(context, 'shell.execute', texts[0] ?? null, 'medium', 'denied-workspace-trust', worst.rule);
        return { allowed: false, refusal };
      }
      const passes = shellLevelAllows(shellLevel, worst.level);
      if (!passes) {
        const refusal = shellLevelRefusal(shellLevel, worst);
        audit(context, 'shell.execute', texts[0] ?? null, worst.level, 'denied-shell-level', worst.rule);
        return { allowed: false, refusal };
      }
      // Critical 人工确认（P1）：七类动作即使在 shell level 3 也必须由本机用户
      // 批准 —— credential access、privilege escalation、destructive system
      // operation、persistence、obfuscated command、download-and-execute、
      // security software modification。模型不能自己授权。
      if (CRITICAL_APPROVAL_CATEGORIES.has(worst.category)) {
        return {
          allowed: true,
          refusal: null,
          pendingApproval: {
            tool: context.tool,
            category: worst.category,
            rule: worst.rule,
            target: texts[0] ?? null,
            session: context.sessionId,
            agent: context.agent
          }
        };
      }
      if (worst.level === 'high' || worst.level === 'critical') {
        audit(context, 'shell.execute', texts[0] ?? null, worst.level, 'allowed-escalated', worst.rule);
      }
    }
  }

  return { allowed: true, refusal: null };
}

/** 触发本地人工确认的 shell 类别（docs/THREAT-MODEL.md 二阶段 P1）。 */
const CRITICAL_APPROVAL_CATEGORIES: ReadonlySet<string> = new Set([
  'credential-access',
  'privilege-escalation',
  'destructive',
  'persistence',
  'obfuscated',
  'pipe-execute',
  'security-software'
]);

function severity(level: string): number {
  switch (level) {
    case 'critical': return 3;
    case 'high': return 2;
    case 'medium': return 1;
    default: return 0;
  }
}
