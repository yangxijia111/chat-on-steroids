/**
 * Bridge 回环 Host 校验测试（docs/THREAT-MODEL.md H2）。
 *
 * DNS rebinding 场景：外部域名解析到 127.0.0.1 后，浏览器请求带着
 * `Origin: https://evil.example`（origin 层已拒）与 `Host: evil.example`。
 * Host 校验是该场景下的独立防线：非回环 Host 一律 403，即使 Origin 缺失。
 */

import http from 'node:http';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { APP_VERSION, BRIDGE_PROTOCOL } from '../src/main/version.js';

// 与 bridge.test.ts 相同的 electron 桩：safeStorage 以明文回环。
vi.mock('electron', () => ({
  safeStorage: {
    isAsyncEncryptionAvailable: vi.fn(async () => true),
    getSelectedStorageBackend: vi.fn(() => 'unknown'),
    encryptStringAsync: vi.fn(async (value: string) => Buffer.from(value, 'utf8')),
    decryptStringAsync: vi.fn(async (buffer: Buffer) => ({ result: buffer.toString('utf8'), shouldReencrypt: false as const, shouldReEncrypt: false }))
  },
  clipboard: {},
  shell: {}
}));

const { defaultConfig, initConfigPath, saveConfig } = await import('../src/main/config.js');
const { initSecretsPath, resetSecretsCacheForTests } = await import('../src/main/secrets.js');
const { initSessionStore, resetSessionStoreForTests } = await import('../src/main/session/store.js');
const { initDurableStore, flushDurable } = await import('../src/main/durable.js');
const { startBridge, stopBridge, resetBridgeForTests } = await import('../src/main/bridge.js');
const { makeTempDir, removeTempDir } = await import('./helpers.js');

let dir: string;
let port: number;

beforeAll(async () => {
  dir = await makeTempDir('clf-bridge-host-');
  initConfigPath(dir);
  initSecretsPath(dir);
  initSessionStore(dir);
  initDurableStore(dir);
  await saveConfig(defaultConfig());
  port = (await startBridge())!;
  expect(port).not.toBeNull();
});

afterAll(async () => {
  await stopBridge();
  resetBridgeForTests();
  resetSessionStoreForTests();
  resetSecretsCacheForTests();
  await flushDurable();
  await removeTempDir(dir);
});

interface Reply {
  status: number;
  body: any;
}

function rawRequest(path: string, headers: Record<string, string>, method = 'GET'): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: '127.0.0.1', port, path, method, headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let body: any = text;
          try {
            body = text ? JSON.parse(text) : null;
          } catch {
            /* 保留原文 */
          }
          resolve({ status: res.statusCode ?? 0, body });
        });
      }
    );
    req.on('error', reject);
    req.end();
  });
}

describe('bridge loopback Host validation', () => {
  it('serves /hello for a loopback Host', async () => {
    const reply = await rawRequest('/hello', {
      host: `127.0.0.1:${port}`,
      'x-extension-version': APP_VERSION,
      'x-extension-protocol': String(BRIDGE_PROTOCOL)
    });
    expect(reply.status).toBe(200);
    expect(reply.body.app).toBe('chat-on-steroids');
  });

  it.each([
    ['evil.example', 'a DNS-rebound domain'],
    ['evil.example:443', 'a DNS-rebound domain with port'],
    ['[::ffff:127.0.0.1]', 'a non-loopback literal']
  ])('refuses Host %s (%s)', async (host) => {
    const headers: Record<string, string> = {
      host,
      'x-extension-version': APP_VERSION,
      'x-extension-protocol': String(BRIDGE_PROTOCOL)
    };
    const reply = await rawRequest('/hello', headers);
    expect(reply.status).toBe(403);
    expect(reply.body.error).toBe('forbidden_host');
  });

  it('refuses a rebound Host even without Origin (curl-style local probe shape)', async () => {
    const reply = await rawRequest('/pair', {
      host: 'rebound.example',
      'content-type': 'application/json',
      'content-length': '0',
      'x-extension-version': APP_VERSION,
      'x-extension-protocol': String(BRIDGE_PROTOCOL)
    }, 'POST');
    expect(reply.status).toBe(403);
    expect(reply.body.error).toBe('forbidden_host');
  });

  it('still refuses a web origin alongside the Host check', async () => {
    const reply = await rawRequest('/hello', {
      host: `localhost:${port}`,
      origin: 'https://chatgpt.com'
    });
    expect(reply.status).toBe(403);
    expect(reply.body.error).toBe('forbidden_origin');
  });
});
