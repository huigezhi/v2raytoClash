import { b64decode } from './base64';
import type { ClashProxy } from './types';
import { safeDecode, splitHostPort } from './utils';

/**
 * 解析 ss:// 链接，兼容两种格式：
 * - SIP002：ss://base64(method:password)@host:port/?plugin=...#name
 *   （userinfo 也可能是明文 method:password）
 * - 旧版：ss://base64(method:password@host:port)#name
 */
export function parseSs(link: string): ClashProxy {
  const body = link.slice('ss://'.length).trim();

  let name = '';
  let main = body;
  const hashIdx = body.indexOf('#');
  if (hashIdx >= 0) {
    name = safeDecode(body.slice(hashIdx + 1));
    main = body.slice(0, hashIdx);
  }

  const qIdx = main.indexOf('?');
  const mainPart = qIdx >= 0 ? main.slice(0, qIdx) : main;
  const query = qIdx >= 0 ? new URLSearchParams(main.slice(qIdx + 1)) : null;

  let method = '';
  let password = '';
  let hostPort = '';

  if (mainPart.includes('@')) {
    const at = mainPart.lastIndexOf('@');
    let userinfo = safeDecode(mainPart.slice(0, at));
    hostPort = mainPart.slice(at + 1);
    if (!userinfo.includes(':')) {
      // SIP002 规范：userinfo 为 base64(method:password)
      try {
        userinfo = b64decode(userinfo);
      } catch {
        throw new Error('ss 链接的 userinfo 解码失败');
      }
    }
    const colon = userinfo.indexOf(':');
    if (colon < 0) throw new Error('ss 链接缺少加密方式或密码');
    method = userinfo.slice(0, colon);
    password = userinfo.slice(colon + 1);
  } else {
    // 旧版格式：整体 base64(method:password@host:port)
    let decoded: string;
    try {
      decoded = b64decode(mainPart);
    } catch {
      throw new Error('ss 链接解码失败');
    }
    const at = decoded.lastIndexOf('@');
    if (at < 0) throw new Error('ss 链接格式无效');
    const userinfo = decoded.slice(0, at);
    const colon = userinfo.indexOf(':');
    if (colon < 0) throw new Error('ss 链接缺少加密方式或密码');
    method = userinfo.slice(0, colon);
    password = userinfo.slice(colon + 1);
    hostPort = decoded.slice(at + 1);
  }

  const { host, port } = splitHostPort(hostPort);
  if (!host || !Number.isFinite(port) || port <= 0) {
    throw new Error('ss 链接缺少服务器地址或端口');
  }
  if (!method) throw new Error('ss 链接缺少加密方式');

  const proxy: ClashProxy = {
    name: name || `${host}:${port}`,
    type: 'ss',
    server: host,
    port,
    cipher: method,
    password,
    udp: true,
  };

  applyPlugin(proxy, query);
  return proxy;
}

/** 将 obfs-local / v2ray-plugin 插件参数映射为 Clash 的 plugin / plugin-opts */
function applyPlugin(proxy: ClashProxy, query: URLSearchParams | null): void {
  const raw = query?.get('plugin');
  if (!raw) return;
  const parts = raw.split(';');
  const plugin = parts[0].toLowerCase();
  const opts: Record<string, string> = {};
  for (const part of parts.slice(1)) {
    const eq = part.indexOf('=');
    if (eq > 0) opts[part.slice(0, eq)] = part.slice(eq + 1);
  }

  if (plugin === 'obfs-local' || plugin === 'simple-obfs') {
    proxy.plugin = 'obfs';
    // obfs-local 的参数键名为 obfs / obfs-host
    const pluginOpts: Record<string, string | boolean> = { mode: opts.obfs || 'http' };
    if (opts['obfs-host']) pluginOpts.host = opts['obfs-host'];
    proxy['plugin-opts'] = pluginOpts;
  } else if (plugin === 'v2ray-plugin') {
    proxy.plugin = 'v2ray-plugin';
    const pluginOpts: Record<string, string | boolean> = {
      mode: opts.mode || 'websocket',
    };
    if (opts.tls) pluginOpts.tls = true;
    if (opts.host) pluginOpts.host = opts.host;
    if (opts.path) pluginOpts.path = opts.path;
    proxy['plugin-opts'] = pluginOpts;
  }
}
