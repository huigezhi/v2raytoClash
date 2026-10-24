import { b64decode } from './base64';
import type { ClashProxy } from './types';

/**
 * 解析 ssr:// 链接：
 * ssr://base64(host:port:protocol:method:obfs:base64pass/?obfsparam=&protoparam=&remarks=)
 */
export function parseSsr(link: string): ClashProxy {
  let decoded: string;
  try {
    decoded = b64decode(link.slice('ssr://'.length).trim());
  } catch {
    throw new Error('ssr 链接 base64 解码失败');
  }

  const slashIdx = decoded.indexOf('/?');
  const main = slashIdx >= 0 ? decoded.slice(0, slashIdx) : decoded;
  const query = slashIdx >= 0 ? new URLSearchParams(decoded.slice(slashIdx + 2)) : null;

  const parts = main.split(':');
  if (parts.length < 6) throw new Error('ssr 链接主体字段不足');
  // IPv6 地址本身含冒号，可能把 host 拆散：合并前面多余的部分
  while (parts.length > 6) {
    parts[0] = `${parts[0]}:${parts[1]}`;
    parts.splice(1, 1);
  }
  const [hostPart, portPart, protocol, cipher, obfs, passB64] = parts;

  const port = Number(portPart);
  if (!hostPart || !Number.isFinite(port) || port <= 0) {
    throw new Error('ssr 链接缺少服务器地址或端口');
  }

  const b64Field = (key: string): string => {
    const raw = query?.get(key);
    if (!raw) return '';
    try {
      return b64decode(raw);
    } catch {
      return raw;
    }
  };

  let password: string;
  try {
    password = b64decode(passB64);
  } catch {
    throw new Error('ssr 链接密码解码失败');
  }

  const proxy: ClashProxy = {
    name: b64Field('remarks') || `${hostPart}:${port}`,
    type: 'ssr',
    server: hostPart,
    port,
    cipher,
    password,
    protocol: protocol || 'origin',
    obfs: obfs || 'plain',
    udp: true,
  };
  const protoparam = b64Field('protoparam') || b64Field('protocolparam');
  if (protoparam) proxy['protocol-param'] = protoparam;
  const obfsparam = b64Field('obfsparam');
  if (obfsparam) proxy['obfs-param'] = obfsparam;
  return proxy;
}
