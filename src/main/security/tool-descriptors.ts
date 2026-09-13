/**
 * 工具安全描述符 — Core 工具与 Plugin 工具共用的安全元数据（威胁模型二阶段 P0）。
 *
 * 一阶段按「核心 Tool 名 → capability」的映射做 worker 降级，第三方 Plugin 工具
 * 不在映射里就绕过了降级。本模块把安全属性从工具名特判中抽出来，统一成一张
 * 描述符表：策略引擎（policy.ts）只读描述符，不再 `if (tool === 'xxx')`。
 *
 * fail-closed 规则：
 *   - 不在表内的工具名（第三方 plugin 工具、未来新增而忘记登记的工具）返回
 *     UNKNOWN_TOOL_DESCRIPTOR：按最高风险处理，restricted worker 一律拒绝；
 *   - plugin 自报的 MCP annotations（readOnlyHint 等）不是安全边界，不参与
 *     判定，仅作审计参考。
 */

import { WINDOWS_COMPUTER_READ_METHODS, WINDOWS_COMPUTER_INPUT_METHODS, WINDOWS_COMPUTER_STATE_INPUT_METHODS } from '../../shared/windows-computer.js';
import type { Capability } from '../../shared/types.js';

export interface ToolSecurityDescriptor {
  /** 该工具要求的 capability（空 = 不由 capability 开关门控，如会话工具）。 */
  capabilities: readonly Capability[];
  risk: 'low' | 'medium' | 'high' | 'critical';
  network?: boolean;
  filesystem?: 'none' | 'read' | 'write';
  processExecution?: boolean;
  desktopControl?: boolean;
  /**
   * restricted worker 下的策略：
   *   allow  = worker 可用（只读/协作工具）；
   *   deny   = worker 禁用（一切写入、执行、桌面控制）；
   *   inherit = 沿用 prime 权限（目前无默认 inherit 的工具，留作显式豁免出口）。
   */
  workerPolicy: 'allow' | 'deny' | 'inherit';
}

/** exec_command/write_stdin 的实际风险由 shell 分类器在运行时定级，表中只给基线。 */

const READ_ONLY: ToolSecurityDescriptor = { capabilities: ['read'], risk: 'low', filesystem: 'read', workerPolicy: 'allow' };

/**
 * 核心工具描述符表。桌面 surface 的方法集合由 shared/windows-computer 生成，
 * 与 surface 声明共用同一来源，避免两份清单漂移。
 */
const CORE_TOOL_DESCRIPTORS: ReadonlyMap<string, ToolSecurityDescriptor> = (() => {
  const map = new Map<string, ToolSecurityDescriptor>();
  map.set('read', READ_ONLY);
  map.set('view_image', READ_ONLY);
  map.set('find', { capabilities: ['search'], risk: 'low', filesystem: 'read', workerPolicy: 'allow' });
  map.set('apply_patch', { capabilities: ['edit'], risk: 'medium', filesystem: 'write', workerPolicy: 'deny' });
  map.set('exec_command', { capabilities: ['command'], risk: 'medium', processExecution: true, workerPolicy: 'deny' });
  map.set('write_stdin', { capabilities: ['command'], risk: 'medium', processExecution: true, workerPolicy: 'deny' });
  map.set('download_artifact', { capabilities: ['saveArtifact'], risk: 'medium', network: true, filesystem: 'write', workerPolicy: 'deny' });
  // 会话/协作工具不触达文件、执行与桌面。
  map.set('session', { capabilities: [], risk: 'low', filesystem: 'none', workerPolicy: 'allow' });
  map.set('update_plan', { capabilities: [], risk: 'low', filesystem: 'none', workerPolicy: 'allow' });
  map.set('agents', { capabilities: [], risk: 'low', filesystem: 'none', workerPolicy: 'allow' });
  map.set('session_finish', { capabilities: [], risk: 'low', filesystem: 'none', workerPolicy: 'allow' });
  // code-mode JS exec（三个 surface 各自的 `exec`）：进程内执行任意 JS 并转调本
  // surface 工具，嵌套调用仍过策略闸，但 JS 本身就是执行面 —— fail-closed 拒绝
  // restricted worker。
  map.set('exec', { capabilities: [], risk: 'medium', processExecution: true, workerPolicy: 'deny' });
  // 桌面 surface。
  map.set('observe', { capabilities: ['screen'], risk: 'medium', desktopControl: true, workerPolicy: 'deny' });
  map.set('computer', { capabilities: ['control', 'clipboardRead', 'clipboardWrite'], risk: 'high', desktopControl: true, workerPolicy: 'deny' });
  for (const method of WINDOWS_COMPUTER_READ_METHODS) {
    map.set(method, { capabilities: ['screen'], risk: 'medium', desktopControl: true, workerPolicy: 'deny' });
  }
  for (const method of WINDOWS_COMPUTER_INPUT_METHODS) {
    const stateOnly = (WINDOWS_COMPUTER_STATE_INPUT_METHODS as readonly string[]).includes(method);
    map.set(method, { capabilities: ['control'], risk: stateOnly ? 'medium' : 'high', desktopControl: true, workerPolicy: 'deny' });
  }
  map.set('read_clipboard', { capabilities: ['clipboardRead'], risk: 'medium', filesystem: 'none', workerPolicy: 'deny' });
  map.set('write_clipboard', { capabilities: ['clipboardWrite'], risk: 'medium', filesystem: 'none', workerPolicy: 'deny' });
  return map;
})();

/**
 * 未知工具的 fail-closed 描述符：按最高风险、全能力面处理。对 prime 不直接拒绝
 * （否则插件/新工具全部不可用），但 restricted worker 一律拒绝，且审计会带上
 * unknown 标记。插件自报的 readOnlyHint 不可信，不改变该判定。
 */
export const UNKNOWN_TOOL_DESCRIPTOR: ToolSecurityDescriptor = {
  capabilities: [],
  risk: 'high',
  network: true,
  filesystem: 'write',
  processExecution: true,
  desktopControl: true,
  workerPolicy: 'deny'
};

/** 取一个工具的安全描述符；未登记的工具返回 UNKNOWN_TOOL_DESCRIPTOR（fail-closed）。 */
export function descriptorFor(tool: string): ToolSecurityDescriptor {
  return CORE_TOOL_DESCRIPTORS.get(tool) ?? UNKNOWN_TOOL_DESCRIPTOR;
}

/** 该工具名是否已登记显式描述符（测试用于断言核心 surface 全覆盖）。 */
export function hasExplicitDescriptor(tool: string): boolean {
  return CORE_TOOL_DESCRIPTORS.has(tool);
}

/** 核心工具名清单（含桌面方法），供覆盖测试遍历。 */
export const DESCRIPTORED_TOOLS: readonly string[] = [...CORE_TOOL_DESCRIPTORS.keys()];
