# nanotun-web

独立的 nanotun 管理后台进程(M2 设计)。

与 `nanotun` 数据面物理隔离 — 不持有 TUN / iptables / control socket(只做 client),
不需要 `CAP_NET_ADMIN`,泄露后影响面只到管理界面。

## 设计要点

- **进程隔离**:与 `nanotun.service` 完全独立,各自的 systemd unit、各自的退出策略。
- **共享 SQLite**:与 nanotun 用同一文件(`/var/lib/nanotun/nanotun.db`);通过
  `migrate` 跨进程 flock 保证迁移安全。
- **独立账号体系**:`web_admins` 新表(argon2id 同款),与 VPN 数据面 `users.psk_hash`
  解耦。Web 账号泄露不会让攻击者获得 VPN 接入权。
- **角色**:`admin`(全功能) / `viewer`(只读)。
- **session**:持久化在 `web_sessions` 表,server 重启不掉登录;改密 / 禁用 admin 自动
  撤销其所有 session。
- **CSRF**:double-submit cookie 模式;所有 POST 均强制 token 校验。
- **TLS**:监听 `0.0.0.0:7443`,启动时若 `cert-dir` 中没有 `cert.pem` + `key.pem`,
  自动生成 ECDSA P-256 自签证书(10 年有效,SAN 含 hostname + 所有非 loopback 网卡 IP)。
- **审计**:每个写操作都过 `store.Audit`,actor = `web:<username>`。
- **观测**:`/healthz` + `/metrics`(Prometheus 文本格式)。

## 启动参数

```text
nanotun-web \
  -listen=0.0.0.0:7443 \
  -db=/var/lib/nanotun/nanotun.db \
  -control-socket=/run/nanotun/control.sock \
  -cert-dir=/etc/nanotun/certs \
  -extra-sans=admin.example.com,1.2.3.4 \
  -session-ttl=43200 \
  -max-login-failures=5 \
  -lockout-seconds=900
```

也可用环境变量覆盖:`NANOTUN_WEB_LISTEN`、`NANOTUN_WEB_DB`、`NANOTUN_WEB_CERT_DIR`、
`NANOTUN_WEB_EXTRA_SANS`、`NANOTUN_WEB_DEBUG`、`NANOTUN_WEB_DISABLE_AUTORELOAD`、
`NANOTUN_CONTROL_SOCKET`。

## 首次使用

1. 装好 `nanotun` 自身(`/var/lib/nanotun/nanotun.db` 已初始化)。
2. 启动 `nanotun-web`,自动生成 self-signed 证书。
3. 浏览器访问 `https://<server>:7443/setup`(忽略证书警告或先把
   `/etc/nanotun/certs/cert.pem` 当 root CA 装进信任库),按表单创建首位管理员。
4. 完成后自动登录,跳到 `/`(总览)。

## 多管理员 + 角色

- `/admins` 列出全部 Web 管理员,可创建 / 改密 / 禁用 / 删除 / 解锁(锁定计数因
  连续登录失败超阈值产生)。
- `admin` 角色 = 全功能;`viewer` 角色 = 只读(进所有 list 页都行,但写操作 403)。
- 安全保护:**不允许把最后一个 enabled admin 删除 / 禁用 / 降级**;**不允许对当前
  登录账号自己执行 disable / delete / 角色变更**。

## 路由总览

| 路径 | 方法 | 说明 |
| --- | --- | --- |
| `/setup` | GET/POST | 仅在 web_admins 为空时可用 |
| `/login`, `/logout` | GET/POST | session 颁/销 |
| `/` | GET | 总览(DB 统计 + 运行时状态 + 最近 10 条审计) |
| `/users` | GET | 用户列表 |
| `/users/new` | GET/POST | 创建用户(自动生成 PSK,一次性展示) |
| `/users/{id}` | GET | 用户详情 |
| `/users/{id}/{verb}` | POST | disable / enable / delete / reset-psk |
| `/devices` | GET | 全部设备(按用户分组,含 fixed_vip 列) |
| `/devices/{id}` | GET | 设备详情(含 lease + route + fixed_vip 配置表单) |
| `/devices/{id}/set-fixed-vip` | POST | 0008 起:给该设备钉死(或清除)固定 vIP |
| `/runtime/mesh-toggle` | POST | 一键切换全网组网模式 ON/OFF(顶栏常驻按钮触发)|
| `/devices/{id}/delete` | POST | 删除设备 |
| `/leases` | GET | vIP 租约一览 |
| `/leases/{device_id}/release` | POST | 释放租约 |
| `/acl`, `/acl/new`, `/acl/{id}/delete` | | ACL 管理 |
| `/routes`, `/routes/{device_id}/{cidr}/{verb}` | | 子网路由审批 |
| `/audit` | GET | 审计日志查询 |
| `/admins`, `/admins/new`, `/admins/{id}/{verb}` | | 多 admin 管理 |
| `/settings` | GET | app_settings 只读展示 |
| `/runtime/reload` | POST | 调 server `/reload?what=acl` |
| `/runtime/kick` | POST | 调 server `/kick` |
| `/healthz` | GET | 健康检查(DB ping) |
| `/metrics` | GET | Prometheus exposition |
| `/static/*` | GET | 嵌入式 CSS |

## 部署到 systemd

`nanotun-web.service` 已附带,与 `nanotun.service` 同款沙盒(`ProtectSystem=strict`,
`ReadWritePaths` 仅 DB/cert/run)。复制到 `/etc/systemd/system/`,
`systemctl daemon-reload && systemctl enable --now nanotun-web`。

## 生产部署建议

- 默认 self-signed 证书仅适合内网 / 跳板。生产建议:把 `-listen` 改成
  `127.0.0.1:7443`,前置 nginx/caddy 走 Let's Encrypt + mTLS。
- 把 `/etc/nanotun/certs/cert.pem` 当 root CA 分发给团队(自签证书的 IsCA=true),
  可以让浏览器停止报警。
- `NANOTUN_WEB_DISABLE_AUTORELOAD=1` 关闭 "改 ACL 后自动通知 server reload" 行为,
  改为运维手动 `systemctl reload nanotun`。
- 监控:让 Prometheus 抓 `/metrics`,Alert 关注 `nanotun-web_errors_total{class="5xx"}`
  斜率与 `nanotun-web_uptime_seconds` 突降。
