# dsh-mobile 主机连接契约

> 把社区插件 `saya-ch/dsh-mobile`（npm `dsh-mobile`）的「安全访问网关」接成 dsh-Go 的第四种主机类型（与 `local / ssh / relay` 并列）。本文是协议契约，代码是事实来源；两者冲突时以 dsh-mobile 源码为准，发现过时直接改这里。

## 1. dsh-mobile 是什么

dsh-mobile 是一个 DSH 社区插件，在电脑上起一个 **HTTPS 网关**（默认监听 `3443`），前置本机 `dsh web`（默认上游 `3080`）。手机端通过该网关继续使用电脑上的会话、工作区、消息与工具。连接通道分两类：

- **局域网**：私有 CA + mDNS/NSD 发现，默认最简单。
- **远程**：Tailscale Funnel / cpolar / cloudflared（快速或命名）/ 自建 FRP / 自有反向代理 / 托管 Caddy；另有实验性 iroh（首期不做）。

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
- 凭据落盘：`deviceToken`（及其摘要）、CA 指纹、origin 存 secure storage；展示名等普通配置存 prefs。
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

- 只做 HTTPS 通道；iroh 不做。
- 局域网自动发现（mDNS/NSD）后置；首期手动 + 扫码。
- 网页推送、`/mobile` 定制、完整设备可达性轮询不在首期。
