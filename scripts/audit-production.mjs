/**
 * 生产依赖审计门禁（二阶段 P2，CI 的 security-audit job 调用）。
 *
 * npm audit --omit=dev --audit-level=high 的可审计版本：例外必须显式列出
 * （包名 + GHSA 编号），且每个例外都要能在 docs/SECURITY-HARDENING.md 的
 * 记录里找到。新增的 high/critical 漏洞让门禁失败；例外之外的一切照旧严格。
 *
 * 用法：node scripts/audit-production.mjs（无参数；退出码非 0 即失败）
 */

import { spawnSync } from 'node:child_process';

/**
 * 已记录的例外。docs/SECURITY-HARDENING.md §3：
 * sharp 0.35.3 的 libheif 通告（GHSA-rgj7-g3m4-5g8c，跨 GHSA-g89c-p67h-r497 与
 * GHSA-2jg2-4ch7-h545 的汇总页）留在受审的 0.35.3 pin 上——修复需要维护者
 * 重新生成 596 个 pinned native source 归档的清单（release 流程），不能在
 * 安全分支上盲动。升级 sharp 后删除本条目即可。
 */
const RECORDED_EXCEPTIONS = [
  { name: 'sharp', advisory: 'GHSA-rgj7-g3m4-5g8c', reason: 'documented pin; native-source inventory regeneration is the maintainers\' reviewed release process' }
];

// Windows 上 npm 是 .cmd，必须经 shell 执行；参数是两个固定字符串，无注入面。
const result = spawnSync('npm', ['audit', '--omit=dev', '--json'], {
  encoding: 'utf8',
  shell: process.platform === 'win32'
});
if (result.error) {
  console.error(`audit-production: could not run npm audit: ${result.error.message}`);
  process.exit(2);
}
let report;
try {
  report = JSON.parse(result.stdout);
} catch {
  console.error('audit-production: npm audit did not return JSON');
  process.exit(2);
}

const failures = [];
for (const vulnerability of Object.values(report.vulnerabilities ?? {})) {
  const entry = vulnerability;
  if (!entry || typeof entry !== 'object') continue;
  const severity = entry.severity;
  if (severity !== 'high' && severity !== 'critical') continue;
  const isExcepted = RECORDED_EXCEPTIONS.some(
    (exception) => exception.name === entry.name &&
      (entry.via ?? []).some((via) => typeof via === 'object' && via.url && via.url.includes(exception.advisory))
  );
  if (!isExcepted) failures.push(`${entry.name} (${severity})`);
}

if (failures.length > 0) {
  console.error(`audit-production: ${failures.length} unexcepted high/critical production vulnerabilit${failures.length === 1 ? 'y' : 'ies'}:`);
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}
console.log(
  `audit-production: production dependencies clean (${RECORDED_EXCEPTIONS.length} recorded exception${RECORDED_EXCEPTIONS.length === 1 ? '' : 's'} acknowledged).`
);
