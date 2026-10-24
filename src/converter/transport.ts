import type { ClashProxy, H2Opts, WsOpts } from './types';

/**
 * 按 v2ray 系分享链接（vless/trojan）的查询参数填充传输层字段：
 * type=ws/grpc/h2（URLSearchParams 已自动完成百分号解码）。
 */
export function applyTransport(proxy: ClashProxy, q: URLSearchParams): void {
  const type = (q.get('type') || 'tcp').toLowerCase();
  if (type === 'ws') {
    proxy.network = 'ws';
    const opts: WsOpts = { path: q.get('path') || '/' };
    const host = q.get('host');
    if (host) opts.headers = { Host: host };
    proxy['ws-opts'] = opts;
  } else if (type === 'grpc') {
    proxy.network = 'grpc';
    proxy['grpc-opts'] = {
      'grpc-service-name': q.get('serviceName') || q.get('path') || '',
    };
  } else if (type === 'h2') {
    proxy.network = 'h2';
    const opts: H2Opts = { path: q.get('path') || '/' };
    const host = q.get('host');
    if (host) opts.host = [host];
    proxy['h2-opts'] = opts;
  }
  // type=tcp 及其它：不设置 network，使用 Clash 默认 TCP
}

/** security/allowInsecure 等布尔型查询参数是否为真 */
export function queryFlag(q: URLSearchParams, key: string): boolean {
  const v = q.get(key);
  return v !== null && ['1', 'true', 'yes'].includes(v.toLowerCase());
}
