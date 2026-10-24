const utf8Decoder = new TextDecoder();

/**
 * 宽容的 base64 解码：兼容无 padding、URL-safe 变体与多余空白，
 * 返回按 UTF-8 解码的字符串（节点名通常是中文）。
 */
export function b64decode(input: string): string {
  let s = input.replace(/\s+/g, '');
  if (s.toLowerCase().startsWith('base64:')) s = s.slice(7);
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4;
  if (pad === 1) throw new Error('无效的 base64 编码');
  if (pad > 0) s += '='.repeat(4 - pad);
  const binary = atob(s);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return utf8Decoder.decode(bytes);
}
