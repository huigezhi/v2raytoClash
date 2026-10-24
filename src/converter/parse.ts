import { parseAnytls } from './anytls';
import { b64decode } from './base64';
import { looksLikeClashYaml, parseClashYaml } from './clashyaml';
import { parseHysteria1 } from './hysteria';
import { parseHysteria2 } from './hysteria2';
import { parseSs } from './ss';
import { parseSsr } from './ssr';
import { parseTrojan } from './trojan';
import type { ClashProxy, ParseResult } from './types';
import { parseTuic } from './tuic';
import { parseVless } from './vless';
import { parseVmess } from './vmess';

const SCHEME_RE = /^([a-z][a-z0-9+.-]*):\/\//i;
const ANY_LINK_RE = /(?:vmess|vless|trojan|ss|ssr|hysteria2|hy2|hysteria|tuic|anytls):\/\//i;
const EMBEDDED_LINK_RE = /(vmess|vless|trojan|ss|ssr|hysteria2|hy2|hysteria|tuic|anytls):\/\//i;

/**
 * 解析用户输入，支持：
 * - 逐行分享链接（vmess/vless/trojan/ss/ssr/hysteria2/hy2/hysteria/tuic/anytls）
 * - 整体 base64 编码的订阅内容
 * - Clash YAML 配置（提取其中的 proxies）
 * 返回 Clash 节点列表与逐条错误，单条失败不影响其余条目。
 */
export function parseInput(input: string): ParseResult {
  const proxies: ClashProxy[] = [];
  const errors: string[] = [];

  const text = input.trim();
  if (!text) return { proxies, errors };

  // Clash YAML 配置：提取 proxies
  if (looksLikeClashYaml(text)) {
    try {
      return dedupeResult(parseClashYaml(text));
    } catch (e) {
      const reason = e instanceof Error ? e.message : String(e);
      return { proxies: [], errors: [reason] };
    }
  }

  let linkText = text;
  // 整体 base64 订阅：内容中没有出现任何链接 scheme 时尝试解码一次
  if (!ANY_LINK_RE.test(linkText)) {
    try {
      const decoded = b64decode(linkText);
      if (ANY_LINK_RE.test(decoded)) linkText = decoded;
    } catch {
      // 保持原样，交给逐行解析报具体错误
    }
  }

  const lines = linkText.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    try {
      proxies.push(parseLine(line));
    } catch (e) {
      const reason = e instanceof Error ? e.message : String(e);
      errors.push(`第 ${i + 1} 行：${reason} —— ${shorten(line)}`);
    }
  }

  return dedupeResult({ proxies, errors });
}

function parseLine(line: string): ClashProxy {
  let target = line;
  let m = target.match(SCHEME_RE);
  if (!m) {
    // 容错：行内带前缀（如 "1. vmess://..."）时从链接起点截取
    const idx = line.search(EMBEDDED_LINK_RE);
    if (idx < 0) throw new Error('不是有效的节点分享链接');
    target = line.slice(idx);
    m = target.match(SCHEME_RE);
    if (!m) throw new Error('不是有效的节点分享链接');
  }

  switch (m[1].toLowerCase()) {
    case 'vmess':
      return parseVmess(target);
    case 'vless':
      return parseVless(target);
    case 'trojan':
      return parseTrojan(target);
    case 'ss':
      return parseSs(target);
    case 'ssr':
      return parseSsr(target);
    case 'hysteria2':
    case 'hy2':
      return parseHysteria2(target);
    case 'hysteria':
      return parseHysteria1(target);
    case 'tuic':
      return parseTuic(target);
    case 'anytls':
      return parseAnytls(target);
    default:
      throw new Error(`暂不支持 ${m[1]}:// 链接`);
  }
}

function dedupeResult(r: ParseResult): ParseResult {
  const used = new Set<string>();
  for (const p of r.proxies) {
    if (!used.has(p.name)) {
      used.add(p.name);
      continue;
    }
    let n = 2;
    while (used.has(`${p.name} (${n})`)) n++;
    p.name = `${p.name} (${n})`;
    used.add(p.name);
  }
  return r;
}

function shorten(line: string): string {
  return line.length > 60 ? `${line.slice(0, 60)}…` : line;
}
