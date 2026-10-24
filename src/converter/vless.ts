import { applyTransport, queryFlag } from './transport';
import type { ClashProxy, RealityOpts } from './types';
import { safeDecode, stripBrackets } from './utils';

/**
 * 解析 vless:// 链接（标准 URI 查询参数格式）。
 * 注意：vless 节点需要 Clash Meta (mihomo) 内核。
 */
export function parseVless(link: string): ClashProxy {
  let url: URL;
  try {
    url = new URL(link);
  } catch {
    throw new Error('vless 链接格式无效');
  }
  const q = url.searchParams;
  const port = Number(url.port);
  if (!url.hostname || !Number.isFinite(port) || port <= 0) {
    throw new Error('vless 链接缺少服务器地址或端口');
  }
  const uuid = safeDecode(url.username);
  if (!uuid) throw new Error('vless 链接缺少用户 UUID');

  const server = stripBrackets(url.hostname);
  const proxy: ClashProxy = {
    name: safeDecode(url.hash.slice(1)) || `${server}:${port}`,
    type: 'vless',
    server,
    port,
    uuid,
    udp: true,
  };

  const flow = q.get('flow');
  if (flow) proxy.flow = flow;

  const security = (q.get('security') || 'none').toLowerCase();
  if (security === 'tls' || security === 'reality' || security === 'xtls') {
    proxy.tls = true;
    const sni = q.get('sni') || q.get('peer');
    if (sni) proxy.servername = sni;
    const fp = q.get('fp');
    if (fp) proxy['client-fingerprint'] = fp;
    const alpn = q.get('alpn');
    if (alpn) proxy.alpn = alpn.split(',').map((s) => s.trim()).filter(Boolean);
    if (security === 'reality') {
      const opts: RealityOpts = {};
      const pbk = q.get('pbk');
      if (pbk) opts['public-key'] = pbk;
      const sid = q.get('sid');
      if (sid) opts['short-id'] = sid;
      proxy['reality-opts'] = opts;
    }
  }

  if (queryFlag(q, 'allowInsecure') || queryFlag(q, 'insecure')) {
    proxy['skip-cert-verify'] = true;
  }

  applyTransport(proxy, q);
  return proxy;
}
