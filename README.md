# v2ray → Clash 配置转换器

一个纯本地的可视化转换工具（功能对标 [hulink](https://github.com/silasxbt/hulink)）：把各类节点分享链接、base64 订阅或已有 Clash 配置，一键转换成 Clash 完整配置或多种订阅格式。

## 使用方式（无需命令行）

1. 双击打开 `dist/index.html`（构建产物，单文件，无任何外部依赖）
2. 输入节点内容，三种方式任选：
   - 把链接 / base64 订阅 / Clash YAML 粘贴进输入框（每行一条链接）
   - 填入订阅 URL 点「获取订阅」在线拉取（可折叠配置 CORS 代理前缀）
   - 点「选择文件」或拖入 txt 文件
3. 点「开始转换」，选择输出格式后「复制」或「下载」
4. 「填入示例」可一键载入内置的虚构测试节点

所有解析均在浏览器本地完成，内容不会上传到任何服务器。

## 支持的输入

| 输入 | 说明 |
| --- | --- |
| `vmess://` | base64 JSON 链接，支持 ws / grpc / h2 / http 传输层、TLS、SNI |
| `vless://` | URI 查询参数格式，支持 TLS、REALITY（pbk/sid）、flow |
| `trojan://` | 含 SNI、ws 传输层、skip-cert-verify |
| `ss://` | SIP002 与旧版整体 base64 格式，支持 obfs / v2ray-plugin |
| `ssr://` | ShadowsocksR（protocol / obfs 及参数） |
| `hysteria2://` `hy2://` | 含 obfs 混淆、SNI、insecure |
| `hysteria://` | Hysteria v1（auth / 上下行带宽 / protocol） |
| `tuic://` | TUIC v5（congestion_control / udp_relay_mode / alpn） |
| `anytls://` | AnyTLS（sni / fp / alpn） |
| base64 订阅 | 整体 base64 编码的链接列表自动解码 |
| Clash YAML | 粘贴已有 Clash 配置，提取其中的 proxies 节点 |

## 支持的输出

| 格式 | 内容 | 下载文件名 |
| --- | --- | --- |
| Clash 完整配置 (YAML) | mixed-port、fake-ip DNS、策略组（节点选择/自动选择）、分流规则 | `config.yaml` |
| 通用 URI 订阅 (Base64) | 全部节点还原为标准分享链接后打包，兼容主流客户端 | `subscription-uri.txt` |
| V2Ray 订阅 (Base64) | 仅 vmess/vless/trojan/ss 节点 | `subscription-v2ray.txt` |
| SS 订阅 (Base64) | 仅 ss 节点 | `subscription-ss.txt` |

## 兼容性

- vmess / trojan / ss 节点：兼容原版 Clash 与 Clash Meta (mihomo)
- vless / hysteria / hysteria2 / tuic / ssr / anytls 节点：需要 Clash Meta (mihomo) 内核——Clash Verge Rev、mihomo-party 等主流客户端默认内置；页面检测到时会显示提示
- 订阅 URL 拉取：仅允许 http/https，拒绝 localhost、环回、私有与保留地址；浏览器直连受 CORS 限制，目标未返回跨域头时会失败，可在「高级」里配置自己的 CORS 代理前缀

## 开发

```bash
npm install     # 安装依赖
npm test        # 运行单元测试（vitest，60 项）
npm run dev     # 本地开发调试
npm run build   # 构建单文件产物到 dist/index.html
```

源码结构：

```
src/
├── main.ts             # 入口与界面事件绑定
├── ui.ts               # 文件读取 / 复制 / 下载等 DOM 工具
├── style.css
└── converter/          # 核心转换逻辑（与 UI 解耦，可独立复用）
    ├── parse.ts        # 输入识别（链接 / base64 / Clash YAML）、分发、去重
    ├── vmess.ts / vless.ts / trojan.ts / ss.ts          # 基础协议解析器
    ├── hysteria2.ts / hysteria.ts / tuic.ts / ssr.ts / anytls.ts
    ├── clashyaml.ts    # Clash YAML 输入解析
    ├── serialize.ts    # 节点 → 分享链接反序列化与订阅打包
    ├── template.ts     # Clash 配置模板（策略组 + 分流规则）
    ├── fetch.ts        # 订阅 URL 拉取与内网地址防护
    └── base64.ts / transport.ts / utils.ts / types.ts
test/
├── converter.test.ts   # 基础协议与配置生成的单元测试
└── protocols.test.ts   # 新协议、Clash YAML、序列化往返与 URL 安全校验测试
examples/sample-links.txt  # 手动测试用示例链接（虚构节点）
```

## 已知限制

- 不支持 Surge 输出格式与节点测速（hulink 的待办项）
- vmess 的 kcp/quic 传输层 Clash 不支持，将按默认 TCP 输出
- 订阅 URL 拉取受浏览器 CORS 限制，未配置代理前缀时仅对返回跨域头的订阅源可用
- 生成的分流规则为通用模板，如有个性化需求可在导入后自行调整

## 许可证

MIT
