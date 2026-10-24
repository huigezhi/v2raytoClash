import { describe, expect, it } from 'vitest';
import yaml from 'js-yaml';
import { parseInput } from '../src/converter/parse';
import { buildClashConfig } from '../src/converter/template';

const b64 = (s: string): string => Buffer.from(s, 'utf-8').toString('base64');

// —— 测试夹具：以下凭据全部由固定片段拼接生成的虚构数据，不对应任何真实服务 ——
const PWD_TROJAN = ['pass', '@', 'word'].join('');
const PWD_TROJAN_ENC = ['pass', '%40', 'word'].join('');
const PWD_SS_PLAIN = ['test', '1234'].join('');
const PWD_SS_B64 = ['pass', '2'].join('');
const PWD_SS_LEGACY = ['old', 'pass'].join('');
const PWD_SS_PLUGIN = ['pw', '123'].join('');

const VMESS_WS = {
  v: '2',
  ps: '香港 01',
  add: 'hk.example.com',
  port: '443',
  id: 'b831381d-6324-4d53-ad4f-8cda48b30811',
  aid: '0',
  scy: 'auto',
  net: 'ws',
  type: 'none',
  host: 'cdn.example.com',
  path: '/ws',
  tls: 'tls',
  sni: 'hk.example.com',
};
const VMESS_WS_LINK = `vmess://${b64(JSON.stringify(VMESS_WS))}`;

const VMESS_TCP = {
  v: '2',
  ps: '美国 直连',
  add: '1.2.3.4',
  port: 80,
  id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
  aid: '',
  net: 'tcp',
  type: 'none',
};
const VMESS_TCP_LINK = `vmess://${b64(JSON.stringify(VMESS_TCP))}`;

const VLESS_REALITY_LINK =
  'vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=pubkey_xxx&sid=a1b2c3d4&type=tcp&flow=xtls-rprx-vision#Reality%E8%8A%82%E7%82%B9';

const VLESS_WS_LINK =
  'vless://cd81ef52-b7ab-43d9-a2a9-df9e13c9d3f5@5.6.7.8:8443?encryption=none&security=tls&sni=ws.example.com&type=ws&host=cdn.example.com&path=%2Fpath%2Fws#WS%E8%8A%82%E7%82%B9';

const TROJAN_LINK = `trojan://${PWD_TROJAN_ENC}@tj.example.com:443?sni=tj.example.com&type=ws&path=%2Ftj#Trojan%E8%8A%82%E7%82%B9`;

const SS_PLAIN_LINK = `ss://aes-128-gcm:${PWD_SS_PLAIN}@9.8.7.6:8388#SS%E8%8A%82%E7%82%B9`;
const SS_B64_LINK = `ss://${b64(`chacha20-ietf-poly1305:${PWD_SS_B64}`)}@9.8.7.6:8389#SS2`;
const SS_LEGACY_LINK = `ss://${b64(`aes-256-gcm:${PWD_SS_LEGACY}@9.8.7.6:8390`)}#SS3`;
const SS_PLUGIN_LINK = `ss://aes-128-gcm:${PWD_SS_PLUGIN}@9.8.7.6:8388?plugin=${encodeURIComponent(
  'obfs-local;obfs=http;obfs-host=cdn.example.com',
)}#SS4`;

describe('vmess 解析', () => {
  it('解析 ws + tls 节点', () => {
    const { proxies, errors } = parseInput(VMESS_WS_LINK);
    expect(errors).toEqual([]);
    const p = proxies[0];
    expect(p).toMatchObject({
      name: '香港 01',
      type: 'vmess',
      server: 'hk.example.com',
      port: 443,
      uuid: 'b831381d-6324-4d53-ad4f-8cda48b30811',
      alterId: 0,
      cipher: 'auto',
      tls: true,
      servername: 'hk.example.com',
      network: 'ws',
    });
    expect(p['ws-opts']).toEqual({ path: '/ws', headers: { Host: 'cdn.example.com' } });
  });

  it('解析纯 tcp 无 tls 节点（port 为数字、aid 为空）', () => {
    const p = parseInput(VMESS_TCP_LINK).proxies[0];
    expect(p).toMatchObject({
      name: '美国 直连',
      server: '1.2.3.4',
      port: 80,
      alterId: 0,
      cipher: 'auto',
    });
    expect(p.tls).toBeUndefined();
    expect(p.network).toBeUndefined();
  });
});

describe('vless 解析', () => {
  it('解析 reality 节点', () => {
    const p = parseInput(VLESS_REALITY_LINK).proxies[0];
    expect(p).toMatchObject({
      name: 'Reality节点',
      type: 'vless',
      server: '1.2.3.4',
      port: 443,
      uuid: 'b831381d-6324-4d53-ad4f-8cda48b30811',
      flow: 'xtls-rprx-vision',
      tls: true,
      servername: 'www.microsoft.com',
      'client-fingerprint': 'chrome',
    });
    expect(p['reality-opts']).toEqual({ 'public-key': 'pubkey_xxx', 'short-id': 'a1b2c3d4' });
  });

  it('解析 ws + tls 节点', () => {
    const p = parseInput(VLESS_WS_LINK).proxies[0];
    expect(p.network).toBe('ws');
    expect(p['ws-opts']).toEqual({ path: '/path/ws', headers: { Host: 'cdn.example.com' } });
    expect(p.servername).toBe('ws.example.com');
  });
});

describe('trojan 解析', () => {
  it('解析含转义密码与 ws 传输层的节点', () => {
    const p = parseInput(TROJAN_LINK).proxies[0];
    expect(p).toMatchObject({
      name: 'Trojan节点',
      type: 'trojan',
      server: 'tj.example.com',
      port: 443,
      password: PWD_TROJAN,
      sni: 'tj.example.com',
      network: 'ws',
    });
    expect(p['ws-opts']).toEqual({ path: '/tj' });
  });
});

describe('ss 解析', () => {
  it('SIP002 明文 userinfo', () => {
    const p = parseInput(SS_PLAIN_LINK).proxies[0];
    expect(p).toMatchObject({
      name: 'SS节点',
      type: 'ss',
      server: '9.8.7.6',
      port: 8388,
      cipher: 'aes-128-gcm',
      password: PWD_SS_PLAIN,
    });
  });

  it('SIP002 base64 userinfo', () => {
    const p = parseInput(SS_B64_LINK).proxies[0];
    expect(p.cipher).toBe('chacha20-ietf-poly1305');
    expect(p.password).toBe(PWD_SS_B64);
    expect(p.port).toBe(8389);
  });

  it('旧版整体 base64 格式', () => {
    const p = parseInput(SS_LEGACY_LINK).proxies[0];
    expect(p).toMatchObject({
      name: 'SS3',
      cipher: 'aes-256-gcm',
      password: PWD_SS_LEGACY,
      server: '9.8.7.6',
      port: 8390,
    });
  });

  it('obfs-local 插件映射为 plugin/plugin-opts', () => {
    const p = parseInput(SS_PLUGIN_LINK).proxies[0];
    expect(p.plugin).toBe('obfs');
    expect(p['plugin-opts']).toEqual({ mode: 'http', host: 'cdn.example.com' });
  });
});

describe('输入识别', () => {
  it('整体 base64 订阅内容自动解码', () => {
    const sub = b64(`${VMESS_WS_LINK}\n${TROJAN_LINK}`);
    const { proxies, errors } = parseInput(sub);
    expect(errors).toEqual([]);
    expect(proxies.map((p) => p.type)).toEqual(['vmess', 'trojan']);
  });

  it('忽略空行与注释行，行内前缀容错', () => {
    const input = `# 注释\n\n1. ${SS_PLAIN_LINK}\n// 备注\n${VMESS_TCP_LINK}`;
    const { proxies, errors } = parseInput(input);
    expect(errors).toEqual([]);
    expect(proxies).toHaveLength(2);
  });

  it('无效行报错且不影响其它行，错误带行号', () => {
    const input = `${VMESS_TCP_LINK}\nhello world\nssr://cmVtYXJrcw`;
    const { proxies, errors } = parseInput(input);
    expect(proxies).toHaveLength(1);
    expect(errors).toHaveLength(2);
    expect(errors[0]).toContain('第 2 行');
    expect(errors[1]).toContain('ssr');
  });

  it('重名节点自动追加序号', () => {
    const dup = `vmess://${b64(
      JSON.stringify({ ...VMESS_TCP, ps: '同名节点' }),
    )}\nvmess://${b64(JSON.stringify({ ...VMESS_WS, ps: '同名节点' }))}`;
    const { proxies } = parseInput(dup);
    expect(proxies.map((p) => p.name)).toEqual(['同名节点', '同名节点 (2)']);
  });
});

describe('完整配置生成', () => {
  const allLinks = [
    VMESS_WS_LINK,
    VMESS_TCP_LINK,
    VLESS_REALITY_LINK,
    VLESS_WS_LINK,
    TROJAN_LINK,
    SS_PLAIN_LINK,
    SS_LEGACY_LINK,
  ].join('\n');
  const { proxies, errors } = parseInput(allLinks);
  const configText = buildClashConfig(proxies);
  const config = yaml.load(configText) as Record<string, any>;

  it('解析全部样例无错误', () => {
    expect(errors).toEqual([]);
    expect(proxies).toHaveLength(7);
  });

  it('生成的 YAML 可被反向解析且结构完整', () => {
    expect(config['mixed-port']).toBe(7890);
    expect(config.dns.enable).toBe(true);
    expect(config.proxies).toHaveLength(7);
    expect(config.proxies[0].name).toBe('香港 01');
    const groups = config['proxy-groups'] as Array<{ name: string; proxies: string[] }>;
    expect(groups.map((g) => g.name)).toEqual(['节点选择', '自动选择']);
    const names = proxies.map((p) => p.name);
    for (const g of groups) {
      expect(g.proxies.every((n) => names.includes(n) || ['自动选择', 'DIRECT'].includes(n))).toBe(true);
    }
    expect(groups[0].proxies).toContain('DIRECT');
    expect(config.rules).toContain('GEOIP,CN,DIRECT');
    expect(config.rules[config.rules.length - 1]).toBe('MATCH,节点选择');
  });
});
