import { describe, expect, it } from 'vitest';
import yaml from 'js-yaml';
import { parseInput } from '../src/converter/parse';
import { assertSubscriptionUrlAllowed } from '../src/converter/fetch';
import {
  buildSsSubscription,
  buildUriSubscription,
  buildV2raySubscription,
  proxyToUri,
} from '../src/converter/serialize';
import { buildClashConfig } from '../src/converter/template';

const b64 = (s: string): string => Buffer.from(s, 'utf-8').toString('base64');
const b64u = (s: string): string =>
  b64(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// —— 以下凭据/密钥均为测试用虚构数据，由固定片段拼接生成 ——
const PWD_HY2 = ['let', 'me', 'in'].join('');
const PWD_TUIC = ['tu', 'pass'].join('');
const PWD_SSR = ['ssr', 'pw'].join('');
const PWD_ANYTLS = ['at', 'pw'].join('');

const HY2_LINK = `hysteria2://${PWD_HY2}@8.8.4.4:8443/?sni=hy2.example.com&obfs=salamander&obfs-password=obpass&insecure=1#HY2%E8%8A%82%E7%82%B9`;
const HY2_ALIAS_LINK = `hy2://${PWD_HY2}@8.8.4.4:8443/#HY2b`;
const TUIC_LINK = `tuic://b831381d-6324-4d53-ad4f-8cda48b30811:${PWD_TUIC}@8.8.8.8:443?sni=tuic.example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#TUIC%E8%8A%82%E7%82%B9`;
const SSR_LINK =
  'ssr://' +
  b64u(
    `9.8.7.6:8388:origin:aes-128-cfb:plain:${b64u(PWD_SSR)}/?obfsparam=${b64u(
      'obparam',
    )}&protoparam=${b64u('protop')}&remarks=${b64u('SSR节点')}`,
  );
const HY1_LINK = `hysteria://9.8.7.6:3670?auth=hy1secret&peer=hy1.example.com&upmbps=100&downmbps=500&protocol=udp&insecure=1#HY1%E8%8A%82%E7%82%B9`;
const ANYTLS_LINK = `anytls://${PWD_ANYTLS}@1.2.3.4:8443?sni=at.example.com&fp=chrome&alpn=h2&insecure=1#AT%E8%8A%82%E7%82%B9`;

describe('hysteria2 解析', () => {
  it('解析完整字段（混淆、SNI、跳过证书）', () => {
    const p = parseInput(HY2_LINK).proxies[0];
    expect(p).toMatchObject({
      name: 'HY2节点',
      type: 'hysteria2',
      server: '8.8.4.4',
      port: 8443,
      password: PWD_HY2,
      sni: 'hy2.example.com',
      obfs: 'salamander',
      'obfs-password': 'obpass',
      'skip-cert-verify': true,
    });
  });

  it('支持 hy2:// 别名', () => {
    const p = parseInput(HY2_ALIAS_LINK).proxies[0];
    expect(p.type).toBe('hysteria2');
  });
});

describe('tuic 解析', () => {
  it('解析 UUID/密码/拥塞控制/中继模式', () => {
    const p = parseInput(TUIC_LINK).proxies[0];
    expect(p).toMatchObject({
      name: 'TUIC节点',
      type: 'tuic',
      server: '8.8.8.8',
      port: 443,
      uuid: 'b831381d-6324-4d53-ad4f-8cda48b30811',
      password: PWD_TUIC,
      sni: 'tuic.example.com',
      'congestion-controller': 'bbr',
      'udp-relay-mode': 'native',
      'skip-cert-verify': true,
    });
    expect(p.alpn).toEqual(['h3']);
  });

  it('缺省参数使用默认值', () => {
    const p = parseInput('tuic://uuid-x:pw@1.2.3.4:443#t').proxies[0];
    expect(p['congestion-controller']).toBe('bbr');
    expect(p['udp-relay-mode']).toBe('native');
  });
});

describe('ssr 解析', () => {
  it('解析主体与 base64 查询参数', () => {
    const p = parseInput(SSR_LINK).proxies[0];
    expect(p).toMatchObject({
      name: 'SSR节点',
      type: 'ssr',
      server: '9.8.7.6',
      port: 8388,
      protocol: 'origin',
      cipher: 'aes-128-cfb',
      obfs: 'plain',
      password: PWD_SSR,
      'obfs-param': 'obparam',
      'protocol-param': 'protop',
    });
  });
});

describe('hysteria v1 解析', () => {
  it('解析认证/上下行带宽/协议', () => {
    const p = parseInput(HY1_LINK).proxies[0];
    expect(p).toMatchObject({
      name: 'HY1节点',
      type: 'hysteria',
      server: '9.8.7.6',
      port: 3670,
      'auth-str': 'hy1secret',
      sni: 'hy1.example.com',
      up: '100',
      down: '500',
      protocol: 'udp',
      'skip-cert-verify': true,
    });
  });
});

describe('anytls 解析', () => {
  it('解析密码/SNI/指纹', () => {
    const p = parseInput(ANYTLS_LINK).proxies[0];
    expect(p).toMatchObject({
      name: 'AT节点',
      type: 'anytls',
      server: '1.2.3.4',
      port: 8443,
      password: PWD_ANYTLS,
      sni: 'at.example.com',
      'client-fingerprint': 'chrome',
      'skip-cert-verify': true,
    });
    expect(p.alpn).toEqual(['h2']);
  });
});

describe('Clash YAML 输入', () => {
  const CLASH_YAML = [
    'mixed-port: 7890',
    'proxies:',
    '  - name: 配置-SS',
    '    type: ss',
    '    server: 1.2.3.4',
    '    port: 8388',
    '    cipher: aes-128-gcm',
    '    password: cfgpw',
    '  - name: 坏条目',
    '    type: vmess',
    '    server: 5.6.7.8',
    '  - name: 配置-HY2',
    '    type: hysteria2',
    '    server: 8.8.4.4',
    '    port: 443',
    '    password: hpw',
  ].join('\n');

  it('提取 proxies，跳过无效条目并报错', () => {
    const { proxies, errors } = parseInput(CLASH_YAML);
    expect(proxies).toHaveLength(2);
    expect(proxies[0]).toMatchObject({ name: '配置-SS', type: 'ss', port: 8388 });
    expect(proxies[1].type).toBe('hysteria2');
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('坏条目');
  });

  it('YAML 语法错误返回错误信息', () => {
    const { proxies, errors } = parseInput('proxies: [name: x');
    expect(proxies).toHaveLength(0);
    expect(errors[0]).toContain('Clash YAML');
  });
});

describe('URI 反向序列化（parse → toUri → parse 往返）', () => {
  const SAMPLES = [HY2_LINK, TUIC_LINK, SSR_LINK, HY1_LINK, ANYTLS_LINK];

  it.each(SAMPLES)('往返保持关键字段：%s', (link) => {
    const first = parseInput(link).proxies[0];
    const again = parseInput(proxyToUri(first)).proxies[0];
    expect(again).toEqual(first);
  });

  it('vmess ws 节点往返保持传输层', () => {
    const p = parseInput(
      'vmess://' +
        b64(
          JSON.stringify({
            v: '2',
            ps: '往返VM',
            add: 'hk.example.com',
            port: '443',
            id: 'b831381d-6324-4d53-ad4f-8cda48b30811',
            aid: '0',
            scy: 'auto',
            net: 'ws',
            host: 'cdn.example.com',
            path: '/ws',
            tls: 'tls',
            sni: 'hk.example.com',
          }),
        ),
    ).proxies[0];
    const again = parseInput(proxyToUri(p)).proxies[0];
    expect(again).toEqual(p);
  });

  it('ss 插件节点往返保持 plugin 配置', () => {
    const p = parseInput(
      `ss://aes-128-gcm:plugpw@9.8.7.6:8388?plugin=${encodeURIComponent(
        'obfs-local;obfs=http;obfs-host=cdn.example.com',
      )}#SS插件`,
    ).proxies[0];
    const again = parseInput(proxyToUri(p)).proxies[0];
    expect(again.plugin).toBe('obfs');
    expect(again['plugin-opts']).toEqual({ mode: 'http', host: 'cdn.example.com' });
  });
});

describe('订阅输出格式', () => {
  const mixed = parseInput([HY2_LINK, TUIC_LINK, HY1_LINK, ANYTLS_LINK,
    'ss://aes-128-gcm:test1234@9.8.7.6:8388#SS',
    'vless://b831381d-6324-4d53-ad4f-8cda48b30811@5.6.7.8:443?encryption=none&security=tls#VL',
  ].join('\n')).proxies;

  it('通用 URI 订阅包含全部节点', () => {
    const decoded = Buffer.from(buildUriSubscription(mixed), 'base64').toString('utf-8');
    const lines = decoded.split('\n');
    expect(lines).toHaveLength(mixed.length);
    expect(lines[0]).toMatch(/^hysteria2:\/\//);
  });

  it('V2Ray 订阅仅包含 vmess/vless/trojan/ss', () => {
    const decoded = Buffer.from(buildV2raySubscription(mixed), 'base64').toString('utf-8');
    const lines = decoded.split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatch(/^ss:\/\//);
    expect(lines[1]).toMatch(/^vless:\/\//);
  });

  it('SS 订阅仅包含 ss 节点；无 ss 节点时报错', () => {
    const decoded = Buffer.from(buildSsSubscription(mixed), 'base64').toString('utf-8');
    expect(decoded).toMatch(/^ss:\/\//);
    const onlyHy2 = parseInput(HY2_LINK).proxies;
    expect(() => buildSsSubscription(onlyHy2)).toThrow('没有可用的 ss 节点');
  });

  it('新类型节点可直接生成完整 Clash 配置', () => {
    const config = yaml.load(buildClashConfig(mixed)) as { proxies: Array<Record<string, unknown>> };
    expect(config.proxies.map((p) => p.type)).toEqual([
      'hysteria2',
      'tuic',
      'hysteria',
      'anytls',
      'ss',
      'vless',
    ]);
  });
});

describe('订阅 URL 安全校验', () => {
  const allowed = [
    'https://sub.example.com/link?token=abc',
    'http://sub.example.com/link',
    'https://8.8.8.8/sub',
    'https://[2606:4700::1111]/sub',
  ];
  const rejected = [
    'ftp://sub.example.com/link',
    'file:///etc/passwd',
    'http://localhost/sub',
    'http://api.localhost/sub',
    'http://box.local/sub',
    'http://127.0.0.1:4173/',
    'http://10.0.0.1/sub',
    'http://172.16.0.1/sub',
    'http://192.168.1.1/sub',
    'http://169.254.1.1/sub',
    'http://0.0.0.0/sub',
    'http://100.64.0.1/sub',
    'http://198.18.0.1/sub',
    'http://224.0.0.1/sub',
    'http://255.255.255.255/sub',
    'http://[::1]/sub',
    'http://[::]/sub',
    'http://[fc00::1]/sub',
    'http://[fe80::1]/sub',
    'http://[::ffff:127.0.0.1]/sub',
    'http://2130706433/sub',
  ];

  it.each(allowed)('放行 %s', (url) => {
    expect(assertSubscriptionUrlAllowed(url).href).toBeTruthy();
  });

  it.each(rejected)('拒绝 %s', (url) => {
    expect(() => assertSubscriptionUrlAllowed(url)).toThrow();
  });
});
