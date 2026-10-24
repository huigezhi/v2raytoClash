import type { ClashProxy } from './types';
import { safeDecode, stripBrackets } from './utils';

/**
 * 解析 hysteria2:// / hy2:// 链接：
 * hysteria2://auth@host:port/?sni=&obfs=salamander&obfs-password=&insecure=1#name
 */
export function parseHysteria2(link: string): ClashProxy {
  let url: URL;
  try {
    url = new URL(link);
  } catch {
    throw new Error('hysteria2 链接格式无效');
  }
  const q = url.searchParams;
  const port = Number(url.port || 443);
  if (!url.hostname || !Number.isFinite(port) || port <= 0) {
    throw new Error('hysteria2 链接缺少服务器地址或端口');
  }
  const password =
    safeDecode(url.username) + (url.password ? `:${safeDecode(url.password)}` : '');
  if (!password) throw new Error('hysteria2 链接缺少认证密码');

  const server = stripBrackets(url.hostname);
  const proxy: ClashProxy = {
    name: safeDecode(url.hash.slice(1)) || `${server}:${port}`,
    type: 'hysteria2',
    server,
    port,
    password,
    udp: true,
  };

  const sni = q.get('sni') || q.get('peer');
  if (sni) proxy.sni = sni;
  const obfs = q.get('obfs');
  if (obfs) {
    proxy.obfs = obfs;
    const obfsPwd = q.get('obfs-password');
    if (obfsPwd) proxy['obfs-password'] = obfsPwd;
  }
  const alpn = q.get('alpn');
  if (alpn) proxy.alpn = alpn.split(',').map((s) => s.trim()).filter(Boolean);

  const insecure = q.get('insecure') ?? q.get('allowInsecure');
  if (insecure && ['1', 'true', 'yes'].includes(insecure.toLowerCase())) {
    proxy['skip-cert-verify'] = true;
  }
  return proxy;
}
