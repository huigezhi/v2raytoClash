import type { ClashProxy } from './types';

const b64encode = (s: string): string => {
  const bytes = new TextEncoder().encode(s);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
};

/** URL-safe base64（无 padding），SIP002 / ssr 序列化用 */
const b64url = (s: string): string => b64encode(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const enc = encodeURIComponent;

/** 从 ClashProxy 形态还原为标准分享链接（参照 hulink 的 node_to_uri） */
export function proxyToUri(p: ClashProxy): string {
  const name = enc(p.name);
  switch (p.type) {
    case 'ss': {
      const auth = b64url(`${p.cipher ?? 'aes-128-gcm'}:${p.password ?? ''}`);
      let uri = `ss://${auth}@${p.server}:${p.port}`;
      const pluginParts: string[] = [];
      if (p.plugin === 'obfs') {
        const o = p['plugin-opts'] ?? {};
        pluginParts.push('obfs-local', `obfs=${o.mode ?? 'http'}`);
        if (o.host) pluginParts.push(`obfs-host=${o.host}`);
      } else if (p.plugin === 'v2ray-plugin') {
        const o = p['plugin-opts'] ?? {};
        pluginParts.push('v2ray-plugin', `mode=${o.mode ?? 'websocket'}`);
        if (o.tls) pluginParts.push('tls');
        if (o.host) pluginParts.push(`host=${o.host}`);
        if (o.path) pluginParts.push(`path=${o.path}`);
      }
      if (pluginParts.length) uri += `?plugin=${encodeURIComponent(pluginParts.join(';'))}`;
      return `${uri}#${name}`;
    }
    case 'vmess': {
      const ws = p['ws-opts'];
      const h2 = p['h2-opts'];
      const grpc = p['grpc-opts'];
      const http = p['http-opts'];
      const cfg = {
        v: '2',
        ps: p.name,
        add: p.server,
        port: String(p.port),
        id: p.uuid ?? '',
        aid: String(p.alterId ?? 0),
        scy: p.cipher ?? 'auto',
        net: p.network === 'http' ? 'tcp' : p.network ?? 'tcp',
        type: p.network === 'http' ? 'http' : 'none',
        host: ws?.headers?.Host ?? h2?.host?.[0] ?? http?.headers?.Host?.[0] ?? '',
        path: ws?.path ?? h2?.path ?? http?.path?.[0] ?? grpc?.['grpc-service-name'] ?? '',
        tls: p.tls ? 'tls' : '',
        sni: p.servername ?? '',
        fp: p['client-fingerprint'] ?? '',
      };
      return `vmess://${b64encode(JSON.stringify(cfg))}`;
    }
    case 'trojan': {
      const q = new URLSearchParams();
      if (p.sni) q.set('sni', p.sni);
      if (p.alpn?.length) q.set('alpn', p.alpn.join(','));
      if (p.network === 'ws') {
        q.set('type', 'ws');
        q.set('path', p['ws-opts']?.path ?? '/');
        const host = p['ws-opts']?.headers?.Host;
        if (host) q.set('host', host);
      }
      if (p['skip-cert-verify']) q.set('allowInsecure', '1');
      const qs = q.size ? `?${q.toString()}` : '';
      return `trojan://${enc(p.password ?? '')}@${p.server}:${p.port}${qs}#${name}`;
    }
    case 'vless': {
      const q = new URLSearchParams();
      q.set('encryption', 'none');
      const reality = p['reality-opts'];
      if (reality) {
        q.set('security', 'reality');
        if (reality['public-key']) q.set('pbk', reality['public-key']);
        if (reality['short-id']) q.set('sid', reality['short-id']);
      } else if (p.tls) {
        q.set('security', 'tls');
      }
      if (p.servername) q.set('sni', p.servername);
      if (p['client-fingerprint']) q.set('fp', p['client-fingerprint']);
      if (p.flow) q.set('flow', p.flow);
      if (p.alpn?.length) q.set('alpn', p.alpn.join(','));
      const ws = p['ws-opts'];
      const h2 = p['h2-opts'];
      const grpc = p['grpc-opts'];
      q.set('type', p.network ?? 'tcp');
      if (p.network === 'ws' && ws) {
        if (ws.path) q.set('path', ws.path);
        const host = ws.headers?.Host;
        if (host) q.set('host', host);
      } else if (p.network === 'h2' && h2) {
        if (h2.path) q.set('path', h2.path);
        const host = h2.host?.[0];
        if (host) q.set('host', host);
      } else if (p.network === 'grpc' && grpc?.['grpc-service-name']) {
        q.set('serviceName', grpc['grpc-service-name']);
      }
      if (p['skip-cert-verify']) q.set('allowInsecure', '1');
      return `vless://${p.uuid}@${p.server}:${p.port}?${q.toString()}#${name}`;
    }
    case 'hysteria2': {
      const q = new URLSearchParams();
      if (p.sni) q.set('sni', p.sni);
      if (p.obfs) {
        q.set('obfs', p.obfs);
        if (p['obfs-password']) q.set('obfs-password', p['obfs-password']);
      }
      if (p.alpn?.length) q.set('alpn', p.alpn.join(','));
      if (p['skip-cert-verify']) q.set('insecure', '1');
      const qs = q.size ? `/?${q.toString()}` : '/';
      return `hysteria2://${enc(p.password ?? '')}@${p.server}:${p.port}${qs}#${name}`;
    }
    case 'tuic': {
      const q = new URLSearchParams();
      q.set('congestion_control', p['congestion-controller'] ?? 'bbr');
      q.set('udp_relay_mode', p['udp-relay-mode'] ?? 'native');
      if (p.sni) q.set('sni', p.sni);
      if (p.alpn?.length) q.set('alpn', p.alpn.join(','));
      if (p['skip-cert-verify']) q.set('allow_insecure', '1');
      return `tuic://${p.uuid ?? ''}:${enc(p.password ?? '')}@${p.server}:${p.port}?${q.toString()}#${name}`;
    }
    case 'ssr': {
      const main = `${p.server}:${p.port}:${p.protocol ?? 'origin'}:${p.cipher ?? 'aes-128-cfb'}:${p.obfs ?? 'plain'}:${b64url(p.password ?? '')}`;
      const q = new URLSearchParams();
      q.set('obfsparam', b64url(p['obfs-param'] ?? ''));
      q.set('protoparam', b64url(p['protocol-param'] ?? ''));
      q.set('remarks', b64url(p.name));
      return `ssr://${b64url(`${main}/?${q.toString()}`)}`;
    }
    case 'hysteria': {
      const q = new URLSearchParams();
      if (p['auth-str']) q.set('auth', p['auth-str']);
      if (p.sni) q.set('peer', p.sni);
      if (p.up) q.set('upmbps', p.up);
      if (p.down) q.set('downmbps', p.down);
      if (p.obfs) q.set('obfs', p.obfs);
      if (p.alpn?.length) q.set('alpn', p.alpn.join(','));
      if (p.protocol) q.set('protocol', p.protocol);
      if (p['skip-cert-verify']) q.set('insecure', '1');
      return `hysteria://${p.server}:${p.port}?${q.toString()}#${name}`;
    }
    case 'anytls': {
      const q = new URLSearchParams();
      if (p.sni) q.set('sni', p.sni);
      if (p.alpn?.length) q.set('alpn', p.alpn.join(','));
      if (p['client-fingerprint']) q.set('fp', p['client-fingerprint']);
      if (p['skip-cert-verify']) q.set('insecure', '1');
      const qs = q.size ? `?${q.toString()}` : '';
      return `anytls://${enc(p.password ?? '')}@${p.server}:${p.port}${qs}#${name}`;
    }
  }
}

/** 按 V2Ray 客户端习惯可接受的链接类型（vmess/vless/trojan/ss） */
export function isV2RayUriType(type: ClashProxy['type']): boolean {
  return type === 'vmess' || type === 'vless' || type === 'trojan' || type === 'ss';
}

/** 通用 URI 订阅：全类型链接打包为 base64 */
export function buildUriSubscription(proxies: ClashProxy[]): string {
  const uris = proxies.map(proxyToUri);
  return b64encode(uris.join('\n'));
}

/** V2Ray 订阅：仅 vmess/vless/trojan/ss，打包为 base64 */
export function buildV2raySubscription(proxies: ClashProxy[]): string {
  const uris = proxies.filter((p) => isV2RayUriType(p.type)).map(proxyToUri);
  if (!uris.length) throw new Error('没有可用的 vmess/vless/trojan/ss 节点');
  return b64encode(uris.join('\n'));
}

/** SS 订阅：仅 ss 节点，打包为 base64 */
export function buildSsSubscription(proxies: ClashProxy[]): string {
  const uris = proxies.filter((p) => p.type === 'ss').map(proxyToUri);
  if (!uris.length) throw new Error('没有可用的 ss 节点');
  return b64encode(uris.join('\n'));
}
