# sforum.connect

SForum 的「用 SForum 账号登录」适配器。Host 拥有账户、回调状态、PKCE 与会话；
本包只验证远端身份，不接触密码、不保存令牌、不建表、不加路由。

## 协议契约

| 端点 | 用途 |
| --- | --- |
| `<base>/api/oauth/authorize` | 浏览器授权入口；`response_type=code` + `state` + PKCE S256 |
| `<base>/api/oauth/token` | 授权码兑换；**JSON 体** + CSRF 双提交（`Cookie: csrf_=…` + `X-Csrf-Token`） |
| `<base>/api/oauth/userinfo` | 读取资料；**只认 `access_token` 查询参数**，Bearer 头到不了插件 |
| `<base>/api/oauth/docs` | 探测用：公开端点目录，声明三个必要端点 |
| `<base>/api/oauth/csrf` | CSRF 握手：GET 会种下 `csrf_` cookie，供 token POST 双提交 |

`<base>` 由设置项 `base_url` 归一化得到（默认 `https://bbs.dalao.me`，允许路径前缀，
剥掉末尾斜杠与误粘贴的 `/api/oauth`，非 loopback 强制 https）。

## 操作

| operation | 输入 | 输出 |
| --- | --- | --- |
| `login.start` / `registration.start` / `link.start` | correlationId、state、codeChallenge、callbackUrl | `status=redirect` + `redirectUrl` |
| `login.complete` / `registration.complete` / `link.complete` | completionToken、codeVerifier、callbackUrl | `providerSubject` + 可选昵称/显示名/邮箱提示 |
| `provider.probe` | 空对象 | `ok` + 稳定 reason + 脱敏 message |

## 稳定错误码

`backend/errors.go` 是唯一事实源。管理端、README 与测试都引用同一组 reason：

- `sforum.base_url_invalid` / `sforum.base_url_insecure`
- `sforum.credentials_missing` / `sforum.client_id_missing` / `sforum.client_secret_missing`
- `sforum.start_input_invalid` / `sforum.pkce_method_unsupported` / `sforum.callback_invalid`
- `sforum.complete_input_invalid`
- `sforum.token_unreachable` / `sforum.token_client_rejected` / `sforum.token_grant_rejected`
- `sforum.token_scope_rejected` / `sforum.token_server_error` / `sforum.token_exchange_failed`
- `sforum.token_malformed` / `sforum.token_empty` / `sforum.timeout`
- `sforum.user_unauthorized` / `sforum.user_request_invalid` / `sforum.user_server_error`
- `sforum.user_fetch_failed` / `sforum.user_unreachable` / `sforum.user_malformed`
- `sforum.subject_missing`
- `sforum.probe_ok` / `sforum.docs_malformed` / `sforum.provider_missing`
- `sforum.endpoint_unreachable` / `sforum.endpoint_error`

## 远端契约的两个坑

1. **token 端点只吃 JSON 体**。SForum 的插件路由声明了请求 schema，Host 只把 JSON 体解析成
   文档；`application/x-www-form-urlencoded` 会在 Host 侧被判 `extensions.route_schema_invalid`（422），
   根本到不了 provider。别照抄 OAuth2 常见的表单写法。
2. **public unsafe 路由要求 CSRF 双提交**。token POST 必须先 `GET /api/oauth/csrf` 拿到
   `csrf_` cookie，再让请求同时携带 `Cookie: csrf_=<value>` 与 `X-Csrf-Token: <value>`；
   否则返回 `403 csrf.invalid`。旧版 provider 没有握手端点时返回 404，插件按无 CSRF 继续。

## 不变量

- 访问令牌只在 `CompleteIdentity` 的调用栈里存在；不落盘、不打日志、不回传。
- 不跟随 HTTP 重定向（`CheckRedirect` 返回 `ErrUseLastResponse`），避免把 client_secret
  交给重定向目标。
- 响应体有上限：令牌/资料 1 MiB，探测 256 KiB。
- 错误文案统一过 `RedactSensitive`；远端 `error_description` 不进入公开契约。
- 远端邮箱仅在 `emailVerified=true` 时作为提示下发。
- 不发送 `scope`：让远端按应用登记范围授权，避免 `invalid_scope`。
- `providerSubject` 原样返回；HMAC digest 由 Host 计算，插件绝不输出 digest。

## 摘要纪律

- 构建：`CGO_ENABLED=0 go build -trimpath -buildvcs=false -o backend/plugin ./`
  （与宿主 `ExtensionPackage.BuildBackend` 同参）。
- 改完源码跑 `scripts/prepare-package.sh`：digest → validate → brand check → extension test。
- 二进制不入库；发布流水线按平台重新构建并写摘要。

## 本地联调

```bash
# 远端应用的回调（loopback http 被远端允许）
http://127.0.0.1:3000/auth/providers/sforum.connect.auth/callback

cd backend && go test ./...
```

**每次改后端源码后的重绑**：dev watcher 会构建并暂存新的精确制品，但 identity 激活行
仍绑定旧 `packageDigest`。此时公开 catalog 会消失、回调以 `auth.provider_unavailable` 失败。
回到「登录方式」把任一开关关再开（或重新保存一次）即可把激活重绑到新制品。这是宿主
exact-artifact 的既定行为，不是插件故障。
