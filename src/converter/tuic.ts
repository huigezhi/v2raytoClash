import type { ClashProxy } from './types';
import { safeDecode, stripBrackets } from './utils';

/**
 * 解析 tuic:// 链接（v5）：
 * tuic://uuid:password@host:port?sni=&alpn=&congestion_control=&udp_relay_mode=#name
 */
export function parseTuic(link: string): ClashProxy {
  let url: URL;
  try {
    url = new URL(link);
  } catch {
    throw new Error('tuic 链接格式无效');
  }
  const q = url.searchParams;
  const port = Number(url.port || 443);
  if (!url.hostname || !Number.isFinite(port) || port <= 0) {
    throw new Error('tuic 链接缺少服务器地址或端口');
  }
  const uuid = safeDecode(url.username);
  const password = url.password ? safeDecode(url.password) : '';
  if (!uuid && !password) throw new Error('tuic 链接缺少 UUID 或密码');

  const server = stripBrackets(url.hostname);
  const proxy: ClashProxy = {
    name: safeDecode(url.hash.slice(1)) || `${server}:${port}`,
    type: 'tuic',
    server,
    port,
    uuid: uuid || undefined,
    password,
    udp: true,
    'congestion-controller': q.get('congestion_control') || q.get('congestion-controller') || 'bbr',
    'udp-relay-mode': q.get('udp_relay_mode') || q.get('udp-relay-mode') || 'native',
  };

  const sni = q.get('sni') || q.get('peer');
  if (sni) proxy.sni = sni;
  const alpn = q.get('alpn');
  if (alpn) proxy.alpn = alpn.split(',').map((s) => s.trim()).filter(Boolean);

  const insecure = q.get('allow_insecure') ?? q.get('allowInsecure') ?? q.get('insecure');
  if (insecure && ['1', 'true', 'yes'].includes(insecure.toLowerCase())) {
    proxy['skip-cert-verify'] = true;
  }
  return proxy;
}
