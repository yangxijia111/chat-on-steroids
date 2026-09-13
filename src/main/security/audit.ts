/**
 * 结构化安全审计日志（docs/THREAT-MODEL.md H7）。
 *
 * 记录每一次安全相关的决策：谁（session/agent）、哪个工具、对什么目标、
 * 风险等级、决策（放行/拒绝/预算耗尽）与原因。与 Activity log（logger.ts）的
 * 分工：Activity 面向诊断、含业务噪音；审计面向事后追责，只含安全事件，
 * 持久化为 JSONL 并有大小上限与轮转。
 *
 * 永不写入秘密：所有自由文本经 logger.redact + redactCredentialText 双重脱敏，
 * 目标字段只保留短摘要。写入失败绝不影响工具执行路径。
 */

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { redact } from '../logger.js';
import { redactCredentialText } from '../redaction.js';
import { getConfig } from '../config.js';

export type AuditRiskLevel = 'low' | 'medium' | 'high' | 'critical';

export type AuditDecision =
  | 'allowed'
  | 'allowed-low-risk'
  | 'allowed-escalated'
  | 'denied-shell-level'
  | 'denied-workspace-trust'
  | 'denied-worker-permission'
  | 'denied-capability'
  | 'denied-budget'
  | 'denied-desktop-target'
  | 'denied-critical-approval'
  | 'approved-critical-once'
  | 'approved-critical-session';

export interface SecurityAuditEntry {
  time: number;
  /** 发起调用的本地会话 id（可能为 null：未归因调用）。 */
  session: string | null;
  /** 发起调用的 agent（prime / worker id / null）。 */
  agent: string | null;
  tool: string;
  /** 动作语义，如 shell.execute / desktop.control / plugin.install。 */
  action: string;
  /** 操作目标的短摘要（命令首 160 字符 / 窗口名 / 文件虚拟路径），脱敏后落盘。 */
  target: string | null;
  risk: AuditRiskLevel | null;
  decision: AuditDecision;
  /** 决策依据，如命中的分类规则。 */
  reason: string | null;
}

const MAX_FILE_BYTES = 1024 * 1024;
const MAX_ROTATIONS = 3;
const MAX_PENDING = 256;

let auditDir: string | null = null;
let auditFile = '';
let pending: string[] = [];
let writing = false;
let writerError = false;

/**
 * 初始化审计存储目录；目录不可用时降级为内存丢弃（审计失败不得拖垮工具）。
 *
 * 注意这里刻意不读、也不缓存 auditLog 开关：初始化发生在 loadConfig() 之前
 * （index.ts 的启动顺序），而开关必须在每次写入时按当前生效配置判定，
 * 否则「重启后 auditLog=false 生效」与「运行时改设置立即生效」都会失真。
 */
export function initAuditLog(dir: string): void {
  auditDir = dir;
  auditFile = path.join(dir, 'audit.jsonl');
  pending = [];
  writerError = false;
  void fs.mkdir(dir, { recursive: true }).catch(() => {
    writerError = true;
  });
}

function sanitize(text: string | null | undefined, cap: number): string | null {
  if (text === null || text === undefined) return null;
  const redacted = redactCredentialText(redact(String(text)));
  // 压缩空白避免命令文本撑爆行预算。
  const compact = redacted.replace(/\s+/g, ' ').trim();
  if (compact === '') return null;
  return compact.slice(0, cap);
}

async function flush(): Promise<void> {
  if (!auditDir || writing) return;
  writing = true;
  try {
    while (pending.length > 0) {
      const lines = pending;
      pending = [];
      let bytes = 0;
      try {
        bytes = (await fs.stat(auditFile)).size;
      } catch {
        bytes = 0;
      }
      if (bytes >= MAX_FILE_BYTES) {
        // 轮转：audit.jsonl → audit.jsonl.1 → …，最旧一份删除。
        for (let index = MAX_ROTATIONS - 1; index >= 1; index -= 1) {
          const from = `${auditFile}.${index}`;
          const to = `${auditFile}.${index + 1}`;
          await fs.rm(to, { force: true });
          await fs.rename(from, to).catch(() => undefined);
        }
        await fs.rename(auditFile, `${auditFile}.1`).catch(() => undefined);
        bytes = 0;
      }
      await fs.appendFile(auditFile, `${lines.join('\n')}\n`, 'utf8');
    }
  } catch {
    // 写失败不重试来源数据（已从 pending 取出），置位避免反复打盘。
    writerError = true;
  } finally {
    writing = false;
  }
}

/**
 * 记录一条安全事件。fire-and-forget：审计写入失败绝不影响工具执行路径。
 * auditLog 开关每次按当前生效配置读取（不缓存过期值），运行时改设置立即生效。
 */
export function recordSecurityAudit(entry: Omit<SecurityAuditEntry, 'time'> & { time?: number }): void {
  if (!(getConfig().security?.auditLog ?? true)) return;
  const full: SecurityAuditEntry = {
    time: entry.time ?? Date.now(),
    session: sanitize(entry.session, 64),
    agent: sanitize(entry.agent, 64),
    tool: sanitize(entry.tool, 64) ?? 'unknown',
    action: sanitize(entry.action, 64) ?? 'unknown',
    target: sanitize(entry.target, 160),
    risk: entry.risk ?? null,
    decision: entry.decision,
    reason: sanitize(entry.reason, 200)
  };
  if (!auditFile || writerError) return;
  pending.push(JSON.stringify(full));
  if (pending.length > MAX_PENDING) {
    // 防御性上限：正常负载远低于此；超限说明 flush 持续失败。
    pending.splice(0, pending.length - MAX_PENDING);
    return;
  }
  void flush();
}

/** 测试复位。 */
export function resetAuditForTests(): void {
  auditDir = null;
  auditFile = '';
  pending = [];
  writing = false;
  writerError = false;
}

/** 测试读取当前待写行。 */
export function auditPendingForTests(): readonly string[] {
  return [...pending];
}
