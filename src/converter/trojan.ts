import { applyTransport, queryFlag } from './transport';
import type { ClashProxy } from './types';
import { safeDecode, stripBrackets } from './utils';

/**
 * 解析 trojan:// 链接。trojan 在 Clash 中始终走 TLS，无需额外 tls 字段。
 */
export function parseTrojan(link: string): ClashProxy {
  let url: URL;
  try {
    url = new URL(link);
  } catch {
    throw new Error('trojan 链接格式无效');
  }
  const q = url.searchParams;
  const port = Number(url.port || 443);
  if (!url.hostname || !Number.isFinite(port) || port <= 0) {
    throw new Error('trojan 链接缺少服务器地址或端口');
  }
  const password = safeDecode(url.username) + (url.password ? `:${safeDecode(url.password)}` : '');
  if (!password) throw new Error('trojan 链接缺少密码');

  const server = stripBrackets(url.hostname);
  const proxy: ClashProxy = {
    name: safeDecode(url.hash.slice(1)) || `${server}:${port}`,
    type: 'trojan',
    server,
    port,
    password,
    udp: true,
  };

  const sni = q.get('sni') || q.get('peer');
  if (sni) proxy.sni = sni;
  const alpn = q.get('alpn');
  if (alpn) proxy.alpn = alpn.split(',').map((s) => s.trim()).filter(Boolean);

  if (queryFlag(q, 'allowInsecure') || queryFlag(q, 'insecure')) {
    proxy['skip-cert-verify'] = true;
  }

  applyTransport(proxy, q);
  return proxy;
}
