import yaml from 'js-yaml';
import type { ClashProxy } from './types';

/** 基础端口 / DNS 等全局设置 + 策略组 + 常用分流规则 */
const BASE_CONFIG = {
  'mixed-port': 7890,
  'allow-lan': false,
  mode: 'rule',
  'log-level': 'info',
  'unified-delay': true,
  'tcp-concurrent': true,
  dns: {
    enable: true,
    listen: '0.0.0.0:1053',
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    nameserver: ['https://223.5.5.5/dns-query', 'https://doh.pub/dns-query'],
  },
};

const RULES = [
  'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
  'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
  'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
  'IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
  'GEOIP,CN,DIRECT',
  'MATCH,节点选择',
];

/** 将节点列表组装为完整 Clash 配置并输出 YAML */
export function buildClashConfig(proxies: ClashProxy[]): string {
  const names = proxies.map((p) => p.name);
  const config = {
    ...BASE_CONFIG,
    proxies,
    'proxy-groups': [
      { name: '节点选择', type: 'select', proxies: ['自动选择', ...names, 'DIRECT'] },
      {
        name: '自动选择',
        type: 'url-test',
        url: 'http://www.gstatic.com/generate_204',
        interval: 300,
        tolerance: 50,
        proxies: names,
      },
    ],
    rules: RULES,
  };
  return yaml.dump(config, { lineWidth: -1, noRefs: true, sortKeys: false });
}
