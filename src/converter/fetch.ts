/** 校验订阅 URL 是否允许拉取：仅 http/https，拒绝 localhost / 环回 / 私有 / 保留地址 */
export function assertSubscriptionUrlAllowed(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new Error('订阅地址格式无效');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('订阅地址仅支持 http/https');
  }

  // URL.hostname 对 IPv6 字面量带方括号，统一去掉
  const host = url.hostname.toLowerCase().replace(/^\[/, '').replace(/\]$/, '');

  if (!host) throw new Error('订阅地址缺少主机名');
  if (host === 'localhost' || host.endsWith('.localhost')) {
    throw new Error('不允许访问 localhost 地址');
  }
  if (host.endsWith('.local') || host.endsWith('.internal')) {
    throw new Error('不允许访问内网域名');
  }
  // 防止十进制/八进制等混淆写法的 IP
  if (/^\d+$/.test(host)) {
    throw new Error('不允许访问该地址');
  }

  if (host.includes(':')) {
    assertIpv6HostSafe(host);
  } else if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    assertIpv4HostSafe(host);
  }
  return url;
}

function assertIpv4HostSafe(host: string): void {
  const octets = host.split('.').map(Number);
  if (octets.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    throw new Error('IP 地址格式无效');
  }
  const [a, b] = octets;
  const reserved =
    a === 0 || // 0.0.0.0/8
    a === 10 || // 10.0.0.0/8
    (a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10 (CGNAT)
    a === 127 || // 环回
    (a === 169 && b === 254) || // 链路本地
    (a === 172 && b >= 16 && b <= 31) || // 私有
    (a === 192 && b === 168) || // 私有
    (a === 192 && b === 0) || // 192.0.0.0/24 与 192.0.2.0/24
    (a === 198 && (b === 18 || b === 19)) || // 198.18.0.0/15 (基准测试)
    (a === 198 && b === 51) || // 198.51.100.0/24
    (a === 203 && b === 0) || // 203.0.113.0/24
    a >= 224; // 组播与保留 (224/4, 240/4, 255.255.255.255)
  if (reserved) throw new Error('不允许访问私有或保留 IP 地址');
}

function assertIpv6HostSafe(rawHost: string): void {
  const host = rawHost.toLowerCase();
  // v4-mapped 形式（::ffff:1.2.3.4，URL 解析器可能规范化为十六进制 ::ffff:7f00:1）
  const mapped = host.match(/^::ffff:(.+)$/);
  if (mapped) {
    const tail = mapped[1];
    let v4: string | null = null;
    if (tail.includes('.')) {
      v4 = tail;
    } else {
      const groups = tail.split(':').map((g) => parseInt(g, 16));
      if (groups.length === 2 && groups.every(Number.isInteger)) {
        v4 = [
          (groups[0] >> 8) & 255,
          groups[0] & 255,
          (groups[1] >> 8) & 255,
          groups[1] & 255,
        ].join('.');
      }
    }
    if (v4) assertIpv4HostSafe(v4);
    return;
  }
  const reserved =
    host === '::' ||
    host === '::1' ||
    /^f[cd]/.test(host) || // fc00::/7 唯一本地
    /^fe[89ab]/.test(host) || // fe80::/10 链路本地
    host.startsWith('2001:db8:'); // 文档保留段
  if (reserved) throw new Error('不允许访问私有或保留 IPv6 地址');
}

export interface FetchOptions {
  /** 可选的 CORS 代理前缀，实际请求 prefix + encodeURIComponent(url) */
  proxyPrefix?: string;
}

/**
 * 拉取订阅内容。浏览器直连受 CORS 限制，目标服务器未返回跨域头时会失败，
 * 可由用户自行配置代理前缀。
 */
export async function fetchSubscription(raw: string, options: FetchOptions = {}): Promise<string> {
  const url = assertSubscriptionUrlAllowed(raw);
  let target = url.href;
  const prefix = options.proxyPrefix?.trim();
  if (prefix) {
    if (!/^https?:\/\//i.test(prefix)) throw new Error('代理前缀必须以 http:// 或 https:// 开头');
    target = prefix + encodeURIComponent(url.href);
  }
  let res: Response;
  try {
    res = await fetch(target, { redirect: 'follow' });
  } catch {
    throw new Error(
      '拉取失败：浏览器跨域(CORS)限制或网络不可达。可复制订阅内容后直接粘贴，或在设置中配置 CORS 代理前缀。',
    );
  }
  if (!res.ok) throw new Error(`订阅服务器返回 HTTP ${res.status}`);
  const text = await res.text();
  if (!text.trim()) throw new Error('订阅内容为空');
  return text;
}
