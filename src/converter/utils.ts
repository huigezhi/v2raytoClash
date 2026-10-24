/** decodeURIComponent 的安全版本：非法转义序列返回原字符串 */
export function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** 去掉 IPv6 主机名两侧的方括号：[::1] → ::1 */
export function stripBrackets(host: string): string {
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

/** 拆分 host:port 或 [ipv6]:port 形式 */
export function splitHostPort(s: string): { host: string; port: number } {
  if (s.startsWith('[')) {
    const close = s.indexOf(']');
    if (close < 0) throw new Error('IPv6 地址格式无效');
    return { host: s.slice(1, close), port: Number(s.slice(close + 2)) };
  }
  const colon = s.lastIndexOf(':');
  if (colon < 0) throw new Error('缺少端口');
  return { host: safeDecode(s.slice(0, colon)), port: Number(s.slice(colon + 1)) };
}
