import './style.css';
import { fetchSubscription } from './converter/fetch';
import { parseInput } from './converter/parse';
import { buildClashConfig } from './converter/template';
import { buildSsSubscription, buildUriSubscription, buildV2raySubscription } from './converter/serialize';
import { META_ONLY_TYPES } from './converter/types';
import type { ClashProxy, ParseResult } from './converter/types';
import { copyText, downloadText, loadFileInto } from './ui';

/** 内置示例链接（全部为虚构节点信息），对齐 hulink「测试示例链接」能力 */
const SAMPLE_LINKS = [
  'vmess://eyJ2IjoiMiIsInBzIjoi56S65L6LLemmmea4ry1XU1MiLCJhZGQiOiJoay5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6ImI4MzEzODFkLTYzMjQtNGQ1My1hZDRmLThjZGE0OGIzMDgxMSIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiJjZG4uZXhhbXBsZS5jb20iLCJwYXRoIjoiL3dzIiwidGxzIjoidGxzIiwic25pIjoiaGsuZXhhbXBsZS5jb20ifQ==',
  'vless://b831381d-6324-4d53-ad4f-8cda48b30811@5.6.7.8:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=pubkey_xxx&sid=a1b2c3d4&type=tcp&flow=xtls-rprx-vision#示例-Reality',
  'trojan://pass%40word@tj.example.com:443?sni=tj.example.com&type=ws&path=%2Ftj#示例-Trojan',
  'ss://aes-128-gcm:test1234@9.8.7.6:8388#示例-SS',
  'hysteria2://letmein@8.8.4.4:8443/?sni=hy2.example.com&obfs=salamander&obfs-password=obpass#示例-Hysteria2',
  'tuic://b831381d-6324-4d53-ad4f-8cda48b30811:tupass@8.8.8.8:443?sni=tuic.example.com&alpn=h3&congestion_control=bbr#示例-TUIC',
].join('\n');

function requireEl<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`缺少元素 #${id}`);
  return el as T;
}

const urlEl = requireEl<HTMLInputElement>('url');
const proxyPrefixEl = requireEl<HTMLInputElement>('proxy-prefix');
const fetchBtn = requireEl<HTMLButtonElement>('fetch');
const inputEl = requireEl<HTMLTextAreaElement>('input');
const fileEl = requireEl<HTMLInputElement>('file');
const sampleBtn = requireEl<HTMLButtonElement>('sample');
const clearBtn = requireEl<HTMLButtonElement>('clear');
const convertBtn = requireEl<HTMLButtonElement>('convert');
const resultCard = requireEl<HTMLElement>('result-card');
const statsEl = requireEl<HTMLElement>('stats');
const metaNotice = requireEl<HTMLElement>('meta-notice');
const formatEl = requireEl<HTMLSelectElement>('format');
const copyBtn = requireEl<HTMLButtonElement>('copy');
const downloadBtn = requireEl<HTMLButtonElement>('download');
const outputEl = requireEl<HTMLPreElement>('output');
const errorsBox = requireEl<HTMLElement>('errors');
const errorList = requireEl<HTMLUListElement>('error-list');

interface State {
  proxies: ClashProxy[];
  errors: string[];
  output: string;
}

const state: State = { proxies: [], errors: [], output: '' };

const OUTPUT_BUILDERS: Record<string, (proxies: ClashProxy[]) => string> = {
  clash: buildClashConfig,
  uri: buildUriSubscription,
  v2ray: buildV2raySubscription,
  ss: buildSsSubscription,
};

const DOWNLOAD_NAMES: Record<string, string> = {
  clash: 'config.yaml',
  uri: 'subscription-uri.txt',
  v2ray: 'subscription-v2ray.txt',
  ss: 'subscription-ss.txt',
};

function renderOutput(): void {
  const format = formatEl.value;
  let text = '';
  let error: string | null = null;
  try {
    if (state.proxies.length === 0) {
      error = null; // 没有节点时由错误区说明
    } else {
      text = OUTPUT_BUILDERS[format](state.proxies);
    }
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }
  state.output = text;
  copyBtn.disabled = !text;
  downloadBtn.disabled = !text;
  outputEl.hidden = !text;
  if (text) outputEl.textContent = text;
  if (error) {
    const li = document.createElement('li');
    li.textContent = error;
    errorList.replaceChildren(li);
    errorsBox.hidden = false;
  } else {
    renderErrors(state.proxies, state.errors);
  }
}

function renderErrors(proxies: ClashProxy[], errors: string[]): void {
  const messages = [...errors];
  if (proxies.length === 0 && messages.length === 0) {
    messages.push(
      '未识别到任何节点内容，请检查输入是否为节点分享链接、base64 订阅或 Clash YAML 配置。',
    );
  }
  if (messages.length === 0) {
    errorsBox.hidden = true;
    return;
  }
  errorList.replaceChildren(
    ...messages.map((msg) => {
      const li = document.createElement('li');
      li.textContent = msg;
      return li;
    }),
  );
  errorsBox.hidden = false;
}

function renderStats(proxies: ClashProxy[]): void {
  const counts = new Map<string, number>();
  for (const p of proxies) counts.set(p.type, (counts.get(p.type) ?? 0) + 1);
  const chips = [`<span class="chip">共 ${proxies.length} 个节点</span>`];
  for (const [type, count] of counts) chips.push(`<span class="chip">${type} × ${count}</span>`);
  statsEl.innerHTML = chips.join('');
}

function convert(): void {
  const r: ParseResult = parseInput(inputEl.value);
  state.proxies = r.proxies;
  state.errors = r.errors;

  resultCard.hidden = false;
  renderStats(r.proxies);
  metaNotice.hidden = !r.proxies.some((p) =>
    (META_ONLY_TYPES as readonly string[]).includes(p.type),
  );
  renderOutput();
  renderErrors(r.proxies, r.errors);
  resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

convertBtn.addEventListener('click', convert);
formatEl.addEventListener('change', renderOutput);

clearBtn.addEventListener('click', () => {
  inputEl.value = '';
  urlEl.value = '';
  inputEl.focus();
});

sampleBtn.addEventListener('click', () => {
  inputEl.value = SAMPLE_LINKS;
  convert();
});

fetchBtn.addEventListener('click', async () => {
  const url = urlEl.value.trim();
  if (!url) {
    urlEl.focus();
    return;
  }
  fetchBtn.disabled = true;
  fetchBtn.textContent = '拉取中…';
  try {
    const content = await fetchSubscription(url, { proxyPrefix: proxyPrefixEl.value });
    inputEl.value = content;
    convert();
  } catch (e) {
    alert(e instanceof Error ? e.message : String(e));
  } finally {
    fetchBtn.disabled = false;
    fetchBtn.textContent = '获取订阅';
  }
});

fileEl.addEventListener('change', async () => {
  const file = fileEl.files?.[0];
  fileEl.value = ''; // 允许重复选择同一个文件
  if (!file) return;
  try {
    await loadFileInto(file, inputEl);
    convert();
  } catch {
    alert('文件读取失败，请重试。');
  }
});

// 拖拽文本文件到输入框
inputEl.addEventListener('dragover', (e) => {
  e.preventDefault();
  inputEl.classList.add('dragover');
});
inputEl.addEventListener('dragleave', () => inputEl.classList.remove('dragover'));
inputEl.addEventListener('drop', async (e) => {
  e.preventDefault();
  inputEl.classList.remove('dragover');
  const file = e.dataTransfer?.files?.[0];
  if (!file) return;
  try {
    await loadFileInto(file, inputEl);
    convert();
  } catch {
    alert('文件读取失败，请重试。');
  }
});

copyBtn.addEventListener('click', async () => {
  if (!state.output) return;
  const ok = await copyText(state.output);
  copyBtn.textContent = ok ? '已复制 ✓' : '复制失败';
  setTimeout(() => (copyBtn.textContent = '复制'), 1500);
});

downloadBtn.addEventListener('click', () => {
  if (!state.output) return;
  downloadText(DOWNLOAD_NAMES[formatEl.value] ?? 'output.txt', state.output);
});
