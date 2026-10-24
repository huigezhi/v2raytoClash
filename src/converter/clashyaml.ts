import yaml from 'js-yaml';
import type { ClashProxy, ParseResult, ProxyType } from './types';

const KNOWN_TYPES: readonly ProxyType[] = [
  'vmess',
  'vless',
  'trojan',
  'ss',
  'hysteria2',
  'hysteria',
  'tuic',
  'ssr',
  'anytls',
];

interface RawProxy {
  name?: unknown;
  type?: unknown;
  server?: unknown;
  port?: unknown;
  [key: string]: unknown;
}

/** 输入内容是否像一份 Clash YAML 配置 */
export function looksLikeClashYaml(text: string): boolean {
  return /^[ \t]*(port|mixed-port|socks-port|allow-lan|mode|log-level|proxies|proxy-groups|rules):/m.test(
    text,
  );
}

/**
 * 从 Clash YAML 配置中提取 proxies 节点列表。
 * 仅保留含 name/type/server/port 的条目，其余字段原样透传。
 */
export function parseClashYaml(text: string): ParseResult {
  const proxies: ClashProxy[] = [];
  const errors: string[] = [];

  let doc: unknown;
  try {
    doc = yaml.load(text);
  } catch (e) {
    const reason = e instanceof Error ? e.message.split('\n')[0] : String(e);
    throw new Error(`Clash YAML 解析失败：${reason}`);
  }
  if (!doc || typeof doc !== 'object' || !Array.isArray((doc as { proxies?: unknown }).proxies)) {
    throw new Error('不是有效的 Clash 配置（缺少 proxies 列表）');
  }

  const rawList = (doc as { proxies: unknown[] }).proxies;
  rawList.forEach((raw, i) => {
    const label = `Clash 节点 #${i + 1}`;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      errors.push(`${label}：条目不是对象`);
      return;
    }
    const p = raw as RawProxy;
    const name = typeof p.name === 'string' ? p.name : '';
    const type = typeof p.type === 'string' ? (p.type.toLowerCase() as ProxyType) : undefined;
    const server = typeof p.server === 'string' ? p.server : '';
    const port = typeof p.port === 'number' ? p.port : Number(p.port);
    if (!name || !server) {
      errors.push(`${label}：缺少 name 或 server${name ? ` —— ${name}` : ''}`);
      return;
    }
    if (!Number.isFinite(port) || port <= 0) {
      errors.push(`${label}：端口无效 —— ${name}`);
      return;
    }
    if (!type || !KNOWN_TYPES.includes(type)) {
      errors.push(`${label}：暂不支持类型 ${String(p.type)} —— ${name}`);
      return;
    }
    proxies.push({ ...p, name, type, server, port } as ClashProxy);
  });

  return { proxies, errors };
}
