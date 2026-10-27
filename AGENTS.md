# AGENTS — sforum-connect

SForum 的「用 SForum 账号登录」插件（OAuth2 客户端 / identity provider 适配器）。
独立仓库，仓库根即外部扩展源根。

- 宿主检出：`~/Code/github/SForum`（同级目录；后端通过 `replace` 解析宿主 SDK）
- 扩展包：`plugins/sforum.connect/`
- 扩展 id：`sforum.connect`

## 命令

```bash
scripts/prepare-package.sh            # build → digest --write → validate → brand check → extension test
cd plugins/sforum.connect/backend && go test ./...
node scripts/brand.mjs                # 重新生成 brand/icon.png 与 social-preview.png
```

宿主 `EXTERNAL_EXTENSION_ROOTS` 已包含本仓库根，保存源文件后 dev watcher 会自动
构建 / 摘要 / 暂存 / 启用，不需要手动跑命令。

## 硬规则

- **摘要必须只由源码决定**：构建一律 `CGO_ENABLED=0 -trimpath -buildvcs=false`，
  与宿主 `ExtensionPackage.BuildBackend` 同参。否则同一份源码在本地与站点两条
  路上产出不同字节，摘要永不收敛。
- **同一扩展 id 只能出现在一个源**：不要同时在 `extensions/dev/` 放副本。
- **`packageFiles` 按路径去重**：同一个文件只能声明一次。
- **不发送 scope**：SForum 的授权端点在省略 scope 时回落到应用登记的权限范围；
  显式发送 `profile email` 会让没登记 email 的应用直接 `invalid_scope`。
- **userinfo 只走 `access_token` 查询参数**：宿主的插件路由会剥掉 Authorization 头。
- **令牌只在调用栈里**：不写日志、不落盘、不返回给 Host。
- **不跟随重定向**：token 端点若 302 到别的主机，跟随会把 client_secret 交给目标。

## 调试

- 插件子进程的 stderr 进宿主日志。
- 探测原因码是稳定契约，见 `backend/errors.go`；改名前先想清楚管理端与文档的引用。
