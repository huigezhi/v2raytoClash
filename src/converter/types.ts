export type ProxyType =
  | 'vmess'
  | 'vless'
  | 'trojan'
  | 'ss'
  | 'hysteria2'
  | 'hysteria'
  | 'tuic'
  | 'ssr'
  | 'anytls';

/** 需要 mihomo (Clash Meta) 内核才能使用的节点类型 */
export const META_ONLY_TYPES: readonly ProxyType[] = [
  'vless',
  'hysteria2',
  'hysteria',
  'tuic',
  'ssr',
  'anytls',
];

export interface WsOpts {
  path?: string;
  headers?: Record<string, string>;
}

export interface GrpcOpts {
  'grpc-service-name'?: string;
}

export interface H2Opts {
  host?: string[];
  path?: string;
}

export interface HttpOpts {
  path?: string[];
  headers?: Record<string, string[]>;
}

export interface RealityOpts {
  'public-key'?: string;
  'short-id'?: string;
}

/** Clash (mihomo) 代理节点（字段顺序即 YAML 输出顺序） */
export interface ClashProxy {
  name: string;
  type: ProxyType;
  server: string;
  port: number;
  uuid?: string;
  password?: string;
  cipher?: string;
  alterId?: number;
  udp?: boolean;
  tls?: boolean;
  /** vless / vmess 的 TLS SNI */
  servername?: string;
  /** trojan / hysteria2 / tuic / hysteria / anytls 的 TLS SNI（mihomo 规范字段名） */
  sni?: string;
  flow?: string;
  'client-fingerprint'?: string;
  'skip-cert-verify'?: boolean;
  alpn?: string[];
  network?: 'ws' | 'grpc' | 'h2' | 'http';
  'ws-opts'?: WsOpts;
  'grpc-opts'?: GrpcOpts;
  'h2-opts'?: H2Opts;
  'http-opts'?: HttpOpts;
  'reality-opts'?: RealityOpts;
  plugin?: string;
  'plugin-opts'?: Record<string, string | boolean>;
  /** hysteria2 obfs 混淆 */
  obfs?: string;
  'obfs-password'?: string;
  /** tuic */
  'congestion-controller'?: string;
  'udp-relay-mode'?: string;
  /** hysteria v1 */
  'auth-str'?: string;
  up?: string;
  down?: string;
  /** ssr / hysteria v1 */
  protocol?: string;
  'protocol-param'?: string;
  'obfs-param'?: string;
}

export interface ParseResult {
  proxies: ClashProxy[];
  /** 解析失败的条目信息（行号或序号 + 原因） */
  errors: string[];
}
