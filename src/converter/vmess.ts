import { b64decode } from './base64';
import type { ClashProxy, HttpOpts, H2Opts, WsOpts } from './types';

/** v2rayN 导出的 vmess JSON 结构（字段宽松，port/aid 等可能为字符串或数字） */
type VmessJson = Record<string, unknown>;

/**
 * 解析 vmess:// 链接（base64 JSON 格式）。
 */
export function parseVmess(link: string): ClashProxy {
  const body = link.slice('vmess://'.length).trim();
  let raw: VmessJson;
  try {
    raw = JSON.parse(b64decode(body)) as VmessJson;
  } catch {
    throw new Error('vmess 内容不是有效的 base64 JSON');
  }

  const str = (key: string, fallback = ''): string => {
    const v = raw[key];
    return v === undefined || v === null ? fallback : String(v);
  };

  const server = str('add');
  const uuid = str('id');
  const port = Number(raw['port']);
  if (!server || !uuid || !Number.isFinite(port) || port <= 0) {
    throw new Error('vmess 节点缺少 add / port / id 必要字段');
  }

  const aidRaw = raw['aid'];
  const alterId =
    aidRaw === undefined || aidRaw === null || aidRaw === '' ? 0 : Number(aidRaw);

  const proxy: ClashProxy = {
    name: str('ps') || `${server}:${port}`,
    type: 'vmess',
    server,
    port,
    uuid,
    alterId: Number.isFinite(alterId) ? alterId : 0,
    cipher: str('scy') || 'auto',
    udp: true,
  };

  const tlsRaw = raw['tls'];
  const tlsOn =
    tlsRaw === true || ['tls', 'true', '1'].includes(String(tlsRaw ?? '').toLowerCase());
  if (tlsOn) {
    proxy.tls = true;
    const sni = str('sni') || str('host');
    if (sni) proxy.servername = sni;
    const fp = str('fp');
    if (fp) proxy['client-fingerprint'] = fp;
  }

  const alpn = str('alpn');
  if (alpn) proxy.alpn = alpn.split(',').map((s) => s.trim()).filter(Boolean);

  const net = str('net', 'tcp').toLowerCase();
  const host = str('host');
  const path = str('path');
  if (net === 'ws') {
    proxy.network = 'ws';
    const opts: WsOpts = { path: path || '/' };
    if (host) opts.headers = { Host: host };
    proxy['ws-opts'] = opts;
  } else if (net === 'grpc') {
    proxy.network = 'grpc';
    proxy['grpc-opts'] = { 'grpc-service-name': path || '' };
  } else if (net === 'h2') {
    proxy.network = 'h2';
    const opts: H2Opts = { path: path || '/' };
    if (host) opts.host = [host];
    proxy['h2-opts'] = opts;
  } else if (net === 'http') {
    proxy.network = 'http';
    const opts: HttpOpts = { path: [path || '/'] };
    if (host) opts.headers = { Host: [host] };
    proxy['http-opts'] = opts;
  } else if (net === 'tcp' && str('type').toLowerCase() === 'http') {
    // tcp + http 伪装头
    proxy.network = 'http';
    const opts: HttpOpts = { path: [path || '/'] };
    if (host) opts.headers = { Host: [host] };
    proxy['http-opts'] = opts;
  }
  // 其余传输层（kcp/quic 等）Clash 不支持，按默认 TCP 输出

  return proxy;
}
