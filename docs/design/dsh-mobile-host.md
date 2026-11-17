# dsh-mobile 主机连接契约

> 把社区插件 `saya-ch/dsh-mobile`（npm `dsh-mobile`）的「安全访问网关」接成 dsh-Go 的第四种主机类型（与 `local / ssh / relay` 并列）。本文是协议契约，代码是事实来源；两者冲突时以 dsh-mobile 源码为准，发现过时直接改这里。

## 1. dsh-mobile 是什么

dsh-mobile 是一个 DSH 社区插件，在电脑上起一个 **HTTPS 网关**（默认监听 `3443`），前置本机 `dsh web`（默认上游 `3080`）。手机端通过该网关继续使用电脑上的会话、工作区、消息与工具。连接通道分两类：

- **局域网**：私有 CA + mDNS/NSD 发现，默认最简单。
- **远程**：Tailscale Funnel / cpolar / cloudflared（快速或命名）/ 自建 FRP / 自有反向代理 / 托管 Caddy；以及 **iroh**（点对点 QUIC，见 §7）。

手机端在两种底层通道之上跑同一套协议：iroh 只是把「到网关的 TCP」换成一条 point-to-point 流，TLS 仍然在电脑上终止，所以 §2 的配对/续期/CSRF、§2.3 的固定 CA 全部照旧。

网关把 `/api/*` 和 WS `/api/remote.mux` 转发到上游 `dsh web`，因此原生客户端可以复用 dsh-Go 现有的 `DshHttpCarrier`，只换底层 TLS 与认证。

## 2. 认证与配对（原生端点）

来源：`src/access.ts`、`src/auth-pages.ts`、`src/gateway.ts`，以及 dsh-mobile Android App 的 `NativeAuthClient.kt`。dsh-Go 是原生客户端，用 `/native-*` 端点（不是浏览器的 `/auth/pair` `/auth/renew`）。

| 端点 | 方法 | 请求体 | 返回 |
|---|---|---|---|
| `/mobile-access/auth/native-pair` | POST | `{ "token": <配对码>, "label": "..." }` | `NativeSession`（含 deviceToken） |
| `/mobile-access/auth/native-renew` | POST | `{ "deviceToken": ... }` | `NativeSession`（不含 deviceToken） |
| `/mobile-access/auth/native-probe` | POST | `{ "deviceToken": ... }` | `NativeProbe`（只探活，不开会话） |
| `/mobile-access/ca.cer` | GET | — | 私有 CA 证书（404 表示走系统信任，不固定） |
| `/mobile-access/discovery` | GET | — | 兼容性发现元数据（JSON） |
| `/mobile-access/metadata` | GET | — | 可选兼容元数据（404 兼容旧网关） |

`NativeSession` 字段：`origin, instanceId, deviceId, deviceToken, deviceExpiresAt, sessionToken, csrfToken, sessionExpiresAt`。
`NativeProbe` 字段：`origin, instanceId, deviceId, deviceExpiresAt`。

### 2.1 Cookie / CSRF（来源 `src/http-security.ts`）

| 项 | 值 |
|---|---|
| 设备 Cookie | `dsh_ma_device`（持久设备令牌，HttpOnly） |
| 会话 Cookie | `dsh_ma_session`（短会话，HttpOnly） |
| CSRF Cookie | `dsh_ma_csrf` |
| CSRF 请求头 | `x-dsh-mobile-csrf` |
| 认证入口前缀 | `/mobile-access` |
| WS 放行路径 | `/api/remote.mux`、`/api/events.mux`、`/api/events.host`、`/sidebar/ws/terminal` |

### 2.2 错误码（稳定、勿映射成文案以外的含义）

`device_revoked`、`device_expired`、`device_limit`、`rate_limited`、`source_network_untrusted`、`authentication_failed`、`forbidden`（CSRF）、`invalid_request`。HTTP 语义：401 认证失败、403 网络来源不可信/CSRF、409 设备上限、429 限流。

### 2.3 TLS 与固定 CA

- 首次配对：先 `GET /mobile-access/ca.cer`（此时可对未固定证书做一次性获取，或按公开入口走系统信任），拿到 CA 后，后续 `pair/renew/probe` 与业务连接都**固定该 CA**（对齐 dsh-mobile App 的 `PinnedTls`）。
- `ca.cer` 返回 404 → 该入口是公开受信证书，不固定，走系统信任。
- 固定 CA 不匹配必须失败关闭，绝不降级成系统信任。

## 3. 配对链接 / 密钥

- 电脑端生成配对二维码/链接/密钥；配对码含短期一次性的 `token`（`openPairing` 产生，`pair` 只消费一次），配对窗口带 `expiresAt`。
- 二维码/链接还需携带 `instanceId`（网关安装身份）用于配对结果核验：`NativeAuthClient` 传入 `expectedInstanceId`，与返回的 `instanceId` 不一致即失败。
- 关键安全属性：**旧设备令牌不发往新 Origin**；Origin 变化（临时隧道地址）必须重新配对，凭据按 Origin 隔离。

## 4. dsh-Go 接入点

- 新 `HostKind.mobile`，与 `local/ssh/relay` 并列；`HostRef.mobile(id, {name})`。
- 复用 `DshHttpCarrier`：`DshConnection` 走 `https://<origin>` + `SecurityContext`（固定 CA）+ 多 Cookie（`dsh_ma_session`/`dsh_ma_device`）+ `x-dsh-mobile-csrf` 头；`DshMux` 经网关 `/api/remote.mux`。
- 凭据落盘：`deviceToken`（及其摘要）、CA 指纹、origin、iroh 私钥存 secure storage；展示名等普通配置存 prefs。
- 通道由 `MobileTransport` 决定：`lan`（直连 `https://<origin>`）或 `iroh`（先建 iroh 流，再在流上跑同一套 HTTPS 请求，见 §7）。
- 上游 DSH 会话如何由网关注入（原生客户端是否需要另取 `dsh-auth` Cookie）以实现时对读 `NativeSessionCookieInstaller.kt` 与 `gateway.ts` 的代理/`browser-auth-cookies.ts` 为准，本契约不替它下结论。

## 5. 生命周期与失败

| 情形 | 处理 |
|---|---|
| 首次连接 | 扫码/粘贴配对链接或密钥 → 拉 CA → `native-pair` → 存 deviceToken+CA 指纹 → 连接 |
| 会话到期 | `native-renew`（deviceToken）换新 sessionToken/csrfToken |
| 设备被撤销/过期 | 401 `device_revoked`/`device_expired` → 停自动重连 → 标记「需重新配对」 |
| 网关不可达 | `failed` + 退避重试，不无限转圈 |
| 网络来源不可信 | 403 `source_network_untrusted` → 提示网络不可信，不重试配对 |
| Origin 变化 | 重新配对，凭据按 Origin 隔离 |

## 6. 首期边界

- 通道：局域网/公网 HTTPS（`MobileTransport.lan`）与 iroh（`MobileTransport.iroh`）。iroh 需要电脑端由 dsh-mobile 托管 iroh 主机端；手机端不跑宿主机角色。
- 局域网自动发现（mDNS/NSD）后置；首期手动 + 扫码。
- 网页推送、`/mobile` 定制、完整设备可达性轮询不在首期。

## 7. iroh 通道

对齐 dsh-mobile 自带的 iroh 主机端（`saya-ch/dsh-mobile-iroh`）：电脑端跑一个 iroh 端点，只接受**已配对**的 EndpointId，把收到的每条流当作原始 TCP 字节转发到本机环回网关；TLS 在电脑上终止，手机端只负责把流接到一个本地端口。

### 7.1 设备身份

- 每台手机持有自己的 iroh 私钥（32 字节），存 secure storage，键 `mobile_iroh_key_<hostId>`（base64）。
- 私钥**不**随主机配置落盘，也不进 prefs；丢失即需要重新配对（`mobileIrohNeedRepair`）。
- 配对时 `SecretKey.generate()` 生成，配对成功后与 deviceToken 一起保存。

### 7.2 配对描述（descriptor）

电脑端展示的 iroh 配对描述是一段 JSON（`version: 1`、`type: "dsh-mobile-iroh-pairing"`），字段恰好十个：
`version, type, endpointId, origin, localPort, irohCode, gatewayToken, caCertificate, instanceId, expiresAt`。

校验（`IrohPairingDescriptor.decode`，对应 dsh-mobile-iroh 的 `validatePairingDescriptor`）：

| 字段 | 约束 |
|---|---|
| `endpointId` / `instanceId` | 64 位小写十六进制 |
| `origin` | 必须等于 `https://<前32hex>.<后32hex>.iroh.localhost:<localPort>` |
| `localPort` | 1024–65535 |
| `irohCode` | 6 位数字 |
| `gatewayToken` | 43 位 base64url |
| `caCertificate` | 非空 base64 DER，解码后 ≤1536 字节，其 sha256 必须等于 `instanceId` |
| `expiresAt` | 未来时间，且不超过 10 分钟 |
| 整体 | ≤ 2200 字节 |

失败原因串（`IrohDescriptorException.reason`）：`descriptor_too_large`、`not_json`、`not_object`、`unexpected_fields`、`unsupported_descriptor`、`invalid_endpoint`、`invalid_port`、`invalid_code`、`invalid_token`、`invalid_instance`、`invalid_expiry`、`invalid_ca`、`invalid_origin`、`ca_fingerprint_mismatch`。

### 7.3 线路协议

ALPN `dsh-mobile-iroh/0`，线路版本 1，控制行是单行 JSON（上限 64 KiB）：

- 握手：手机端开一条双向流，写 `{"version":1,"type":"pair","code":"<6位>","name":"<设备名>"}`（已配对后重连写 `"type":"hello"`，不带 `code`），读取一行回复：`pair-ok` / `hello-ok` / `pair-fail`（带 `reason`）。
- 数据：每条 TCP 连接开一条流，先写 `{"version":1,"type":"proxy"}\n`，之后是原始字节。

握手失败按原因分类（`irohError`）：`handshake_refused`、`pair-fail`、`not_paired`、`unknown_endpoint`、`endpoint_mismatch`、`bad_handshake` → `authFailed` + `irohPeerRefused`，不重试；其余（`connect_timeout`、`endpoint_closed`、`relay_unreachable` 等）→ `unreachable` + `irohTunnelFailed`，退避重试。

### 7.4 数据面接线

1. `IrohChannel.open(endpointId, secretKey, name)` → `Endpoint.bind` + `connect` + 握手。
2. `LocalForwarder.bind(channel.openTunnel)` 在 `127.0.0.1` 上开一个临时端口，每条到该端口的 TCP 连接对应一条 iroh 流。
3. `IrohTunnelHttpClient` 把 `DshConnection` 的 `connectionFactory` 指向那个本地端口，并把 `iroh.localhost` 名字保留为 HTTP Host/SNI，仅信任描述里的 CA（不加载系统根证书）；缺失 CA 时拒绝连接。
4. 之后与 §2 完全一致：`native-renew` → `dsh_ma_session`/`dsh_ma_device` Cookie + `x-dsh-mobile-csrf` + `Origin` → `/api/remote.mux`。

因为 TLS 在电脑上终止，iroh 只提供可达性与端到端加密的传输层；应用层认证、CSRF、CA 固定都不变，失败时也不会降级到明文。

### 7.5 保存配置与生命周期边界

每次连接使用同一份配置快照。在发送设备令牌前，重新校验派生 origin、端点、端口及 SecretStore CA 的 SHA-256 与 instanceId/caFingerprint 的绑定；已有 iroh 私钥但配置被改为 LAN 时拒绝连接。损坏或丢失 CA/私钥必须重新配对，不回退到系统根证书。信任确认后还会重新检查描述有效期。

同一链接的 open/reconnect 是 single-flight；close 会唤醒等待 secrets/renew/mux 的任务，等待尚未结束的原生拨号并清理晚到资源，构造中途失败也释放 forwarder 和 endpoint。QUIC 的发送队列复制生产者缓冲区、按序写入，所有写入结束后才发送 FIN；写入失败会传播到 sink.done 并关闭隧道，而不是静默丢包。
