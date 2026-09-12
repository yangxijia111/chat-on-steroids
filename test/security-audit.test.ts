/**
 * 安全审计日志与凭据脱敏测试（docs/THREAT-MODEL.md H7/M1）。
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { initConfigPath, defaultConfig, saveConfig } from '../src/main/config.js';
import { initAuditLog, recordSecurityAudit, resetAuditForTests } from '../src/main/security/audit.js';
import { redactCredentialText } from '../src/main/redaction.js';
import { redact } from '../src/main/logger.js';
import { makeTempDir, removeTempDir } from './helpers.js';

let dir: string;

beforeAll(async () => {
  dir = await makeTempDir('clf-security-audit-');
  initConfigPath(dir);
  const base = defaultConfig();
  await saveConfig({ ...base, security: { ...base.security, auditLog: true } });
  initAuditLog(path.join(dir, 'security'));
});

afterAll(async () => {
  resetAuditForTests();
  await removeTempDir(dir);
});

async function flushAndGet(): Promise<Array<Record<string, unknown>>> {
  // 审计写入是异步批处理的；短轮询等待落盘。
  for (let attempt = 0; attempt < 50; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 20));
    try {
      const text = await fs.readFile(path.join(dir, 'security', 'audit.jsonl'), 'utf8');
      const lines = text.split('\n').filter(Boolean);
      if (lines.length > 0) return lines.map((line) => JSON.parse(line) as Record<string, unknown>);
    } catch {
      /* 文件尚未创建 */
    }
  }
  return [];
}

describe('security audit log', () => {
  it('records a structured decision with all fields', async () => {
    recordSecurityAudit({
      session: 'session-1',
      agent: 'worker-1',
      tool: 'exec_command',
      action: 'shell.execute',
      target: 'npm install',
      risk: 'medium',
      decision: 'allowed-escalated',
      reason: '项目内包安装'
    });
    const entries = await flushAndGet();
    const entry = entries.find((row) => row['tool'] === 'exec_command');
    expect(entry).toBeDefined();
    expect(entry!['session']).toBe('session-1');
    expect(entry!['agent']).toBe('worker-1');
    expect(entry!['action']).toBe('shell.execute');
    expect(entry!['risk']).toBe('medium');
    expect(entry!['decision']).toBe('allowed-escalated');
    expect(typeof entry!['time']).toBe('number');
  });

  it('redacts credentials in every free-text field', async () => {
    const githubToken = ['ghp_', '0123456789abcdefghijklmnopqrstuvwxyzAB'].join('');
    const openRouterKey = ['sk-or-v1-', 'abcdefghijklmnopqrstuvwxyz012345'].join('');
    recordSecurityAudit({
      session: null,
      agent: null,
      tool: 'exec_command',
      action: 'shell.execute',
      target: `curl -H "Authorization: Bearer ${githubToken}" https://x`,
      risk: 'critical',
      decision: 'denied-shell-level',
      reason: `token ${openRouterKey} leaked in reason`
    });
    const entries = await flushAndGet();
    const entry = entries.find((row) => row['decision'] === 'denied-shell-level');
    expect(String(entry!['target'])).not.toContain(githubToken);
    expect(String(entry!['reason'])).not.toContain(openRouterKey);
  });
});

describe('credential redaction patterns', () => {
  // 测试用的键均为公开文档示例形状，由片段拼接构造，源码中不出现完整字面量。
  const openAiKey = ['sk-proj-', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ12'].join('');
  const anthropicKey = ['sk-ant-api03-', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234'].join('');
  const openRouterKey = ['sk-or-v1-', 'abcdefghijklmnopqrstuvwxyz012345'].join('');
  const githubKey = ['ghp_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'].join('');
  const githubPat = ['github_pat_11ABCDEFG0', 'abcdefghijklmnopqrstuvwxyzA'].join('');
  const awsKey = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
  const slackToken = ['xoxb-123456789012-1234567890123-', 'abcdefghijklmnopqrstuvwx'].join('');
  const googleKey = ['AIzaSy', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567'].join('');

  it.each([
    [openAiKey, 'openai'],
    [anthropicKey, 'anthropic'],
    [openRouterKey, 'openrouter'],
    [githubKey, 'github'],
    [githubPat, 'github-pat'],
    [awsKey, 'aws'],
    [slackToken, 'slack'],
    [googleKey, 'google']
  ])('%s shapes are redacted', (secret) => {
    const result = redactCredentialText(`token: ${secret}`);
    expect(result).not.toContain(secret);
    expect(result).toContain('[redacted]');
  });

  it('keeps the Bearer label but masks the token', () => {
    const token = ['abcdef1234567890', 'abcdef'].join('');
    const result = redactCredentialText(`Authorization: Bearer ${token}`);
    expect(result).toContain('Bearer [redacted]');
    expect(result).not.toContain(token);
  });

  it('does not redact ordinary identifiers, hashes or prose', () => {
    const plain = 'The file sha256 a1b2c3d4e5f6 says hello world 42 times';
    expect(redactCredentialText(plain)).toBe(plain);
    expect(redactCredentialText('see docs/README.md section 3.2')).toBe('see docs/README.md section 3.2');
  });

  it('logger redact masks jwt and long opaque tokens', () => {
    const jwt = ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'eyJzdWIiOiIxMjM0NTY3ODkwIn0', 'dozjgNryP4J3jVmNHl0w5N65IwdjAqTFmpzg5uoA0'].join('.');
    expect(redact(`jwt ${jwt}`)).not.toContain('eyJhbGciOi');
  });
});
