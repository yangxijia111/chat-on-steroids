/**
 * Recognizable API credentials in authored text, including keys pasted into browser form/code
 * arguments rather than configured as plugin secrets. Do not treat arbitrary long identifiers,
 * hashes or image bytes as credentials: those must survive tool results and exact recordings.
 *
 * 安全加固（docs/THREAT-MODEL.md M1）后覆盖范围扩大到常见厂商的可识别 token 形状：
 * OpenAI/Anthropic/OpenRouter、GitHub PAT、AWS 访问键、Slack、Google、Stripe 与
 * 通用 Bearer。匹配依赖各厂商公开的前缀与字符集，不猜测任意字符串。
 */

/** 各厂商 token 的「前缀 + 字符集」形状；命中即整段替换为 [redacted]。 */
const CREDENTIAL_PATTERNS: readonly RegExp[] = [
  // OpenAI 家族（原有行为，保持）。
  /\bsk-(?:or-v1-|proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/g,
  // Anthropic。
  /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  // GitHub PAT（classic gh[ou]… / fine-grained github_pat_…）。
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{30,}\b/g,
  // AWS 访问键 id。
  /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
  // Slack。
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
  // Google API key / OAuth。
  /\bAIza[0-9A-Za-z_-]{30,}\b/g,
  /\bya29\.[0-9A-Za-z_-]{20,}\b/g,
  // Stripe。
  /\b(?:sk|rk)_(?:test_)?live_[0-9a-zA-Z]{20,}\b/g,
  // 通用 Bearer token（Authorization 头常见形状）。
  /\bBearer\s+[A-Za-z0-9._~+/-]{16,}/g
];

export function redactCredentialText(text: string): string {
  let result = text;
  for (const pattern of CREDENTIAL_PATTERNS) {
    result = result.replace(pattern, (match) => {
      // Bearer 前缀保留，凭据本身打码，便于阅读日志时识别该处曾有凭据。
      if (match.startsWith('Bearer')) return 'Bearer [redacted]';
      return '[redacted]';
    });
  }
  return result;
}
