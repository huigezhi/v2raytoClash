import type { ClashProxy } from './types';
import { safeDecode, stripBrackets } from './utils';

/**
 * 解析 hysteria:// 链接（v1）：
 * hysteria://host:port?auth=&peer=&upmbps=&downmbps=&protocol=&obfs=#name
 */
export function parseHysteria1(link: string): ClashProxy {
  let url: URL;
  try {
    url = new URL(link);
  } catch {
    throw new Error('hysteria 链接格式无效');
  }
  const q = url.searchParams;
  const port = Number(url.port || 443);
  if (!url.hostname || !Number.isFinite(port) || port <= 0) {
    throw new Error('hysteria 链接缺少服务器地址或端口');
  }

  const server = stripBrackets(url.hostname);
  const proxy: ClashProxy = {
    name: safeDecode(url.hash.slice(1)) || `${server}:${port}`,
    type: 'hysteria',
    server,
    port,
    udp: true,
  };

  const auth = q.get('auth') || q.get('auth_str');
  if (auth) proxy['auth-str'] = safeDecode(auth);
  const sni = q.get('peer') || q.get('sni');
  if (sni) proxy.sni = sni;
  const up = q.get('upmbps') || q.get('up');
  if (up) proxy.up = up;
  const down = q.get('downmbps') || q.get('down');
  if (down) proxy.down = down;
  const obfs = q.get('obfs');
  if (obfs) proxy.obfs = obfs;
  const alpn = q.get('alpn');
  if (alpn) proxy.alpn = alpn.split(',').map((s) => s.trim()).filter(Boolean);
  const protocol = q.get('protocol');
  if (protocol) proxy.protocol = protocol;

  const insecure = q.get('insecure') ?? q.get('allowInsecure');
  if (insecure && ['1', 'true', 'yes'].includes(insecure.toLowerCase())) {
    proxy['skip-cert-verify'] = true;
  }
  return proxy;
}
