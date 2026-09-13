/**
 * Critical Action 本地人工确认（威胁模型二阶段 P1）。
 *
 * shell level 3 不再自动放行 critical 命令。凭据访问、提权、广域破坏、持久化、
 * 混淆命令、下载即执行、安全软件变更这七类动作在执行前必须弹出 Electron 本地
 * 确认框，由人决定：
 *
 *   - Allow once：仅本次调用放行；
 *   - Allow for session：本应用运行期间，同类（category+rule）不再询问；
 *   - Deny：拒绝（默认按钮；超时/无窗口同样拒绝）。
 *
 * Critical 永远不能由模型自己授权：确认框只由真实用户交互驱动，模型可见的
 * 文案不含任何可影响本层的信息。决策写入安全审计日志。
 */

import { dialog, type BrowserWindow } from 'electron';
import { recordSecurityAudit } from './audit.js';

export type CriticalApprovalDecision = 'allow-once' | 'allow-session' | 'deny';

export interface CriticalApprovalRequest {
  tool: string;
  /** shell 分类类别（credential-access / pipe-execute / …）。 */
  category: string;
  /** 命中的分类规则说明，展示给用户。 */
  rule: string;
  /** 命令/目标摘要（已脱敏由 audit 层负责，这里原文只进对话框）。 */
  target: string | null;
  session: string | null;
  agent: string | null;
}

export type ApprovalPrompt = (request: CriticalApprovalRequest, window: BrowserWindow | null) => Promise<CriticalApprovalDecision>;

/** 等待用户的时间上限；超时按 Deny（fail-closed）。 */
const APPROVAL_TIMEOUT_MS = 120_000;

let resolveWindow: (() => BrowserWindow | null) | null = null;
let promptOverride: ApprovalPrompt | null = null;
/** session 级批准缓存：category+rule+tool。 */
const sessionApprovals = new Set<string>();
/** 进行中的确认（并发同类请求只弹一个框）。 */
const inFlight = new Map<string, Promise<CriticalApprovalDecision>>();

/** 由主进程接线（ipc.ts 注册时）注入主窗口解析器。 */
export function initApprovalPrompt(getWindow: () => BrowserWindow | null): void {
  resolveWindow = getWindow;
}

/** 测试注入 prompt 实现；传 null 恢复默认。 */
export function setApprovalPromptForTests(prompt: ApprovalPrompt | null): void {
  promptOverride = prompt;
}

function sessionKeyOf(request: CriticalApprovalRequest): string {
  return `${request.tool}::${request.category}::${request.rule}`;
}

const BUTTONS = ['Allow once', 'Allow for session', 'Deny'] as const;
const DENY_INDEX = 2;

/** 默认实现：Electron 对话框；无窗口或对话框失败一律 Deny。 */
const dialogPrompt: ApprovalPrompt = async (request, window) => {
  if (!window || window.isDestroyed()) return 'deny';
  const detail = [
    `Tool: ${request.tool}`,
    `Reason: ${request.rule}`,
    request.target ? `Command: ${request.target.slice(0, 300)}` : null
  ]
    .filter((line): line is string => line !== null)
    .join('\n');
  const result = await dialog.showMessageBox(window, {
    type: 'warning',
    title: 'Critical action requires approval',
    message: 'A critical security-sensitive action is about to run.',
    detail,
    buttons: [...BUTTONS],
    defaultId: DENY_INDEX,
    cancelId: DENY_INDEX,
    noLink: true
  });
  return result.response === 0 ? 'allow-once' : result.response === 1 ? 'allow-session' : 'deny';
};

/**
 * 解决一次 critical 确认。同类并发请求共享同一个在途确认。
 * 决策与审计都在这里：allow-once 不缓存，allow-session 记入会话缓存。
 */
export async function resolveCriticalApproval(request: CriticalApprovalRequest): Promise<CriticalApprovalDecision> {
  const key = sessionKeyOf(request);
  if (sessionApprovals.has(key)) {
    recordSecurityAudit({
      session: request.session,
      agent: request.agent,
      tool: request.tool,
      action: 'shell.execute',
      target: request.target,
      risk: 'critical',
      decision: 'approved-critical-session',
      reason: request.rule
    });
    return 'allow-session';
  }
  const existing = inFlight.get(key);
  if (existing) return existing;
  const run = (async () => {
    const prompt = promptOverride ?? dialogPrompt;
    const window = resolveWindow?.() ?? null;
    let decision: CriticalApprovalDecision;
    try {
      decision = await Promise.race([
        prompt(request, window),
        new Promise<CriticalApprovalDecision>((resolve) => setTimeout(() => resolve('deny'), APPROVAL_TIMEOUT_MS))
      ]);
    } catch {
      decision = 'deny';
    }
    if (decision === 'allow-session') sessionApprovals.add(key);
    recordSecurityAudit({
      session: request.session,
      agent: request.agent,
      tool: request.tool,
      action: 'shell.execute',
      target: request.target,
      risk: 'critical',
      decision:
        decision === 'allow-session'
          ? 'approved-critical-session'
          : decision === 'allow-once'
            ? 'approved-critical-once'
            : 'denied-critical-approval',
      reason: request.rule
    });
    return decision;
  })();
  inFlight.set(key, run);
  try {
    return await run;
  } finally {
    inFlight.delete(key);
  }
}

/** 测试复位（清 session 批准缓存）。 */
export function resetApprovalForTests(): void {
  sessionApprovals.clear();
  inFlight.clear();
  promptOverride = null;
  resolveWindow = null;
}
