# 发布流程（硬门禁）

这份文档是**唯一**允许的发版路径。合并到 `main` 不等于可以发版；打出
`dist/nanotun-*.tar.gz` 之前必须过完下面的门。

三机 e2e 跑不进 GitHub Actions（要 root、要真机、要测试服口令），所以 CI 绿只覆盖
**合并**门槛；**发版**门槛由本仓库脚本强制，不能靠记性。

## 两道门

| 门 | 拦住什么 | 怎么过 |
|---|---|---|
| **合并门**（CI） | 编译坏了、格式漂了、单测红了 | `go build` / `vet` / `gofmt` / `go test ./...` / e2e selftest |
| **发版门**（本机 + 三机） | 「CI 绿但真机行为没验」就打包 | `scripts/release/cut.sh`：单测 + **与 HEAD 对齐的 e2e 戳** + 打包 |

直接跑 `scripts/build-release.sh` **会被拒绝**，除非设了
`NANOTUN_RELEASE_I_KNOW=1`（调试用；发出版本包不要用）。

## 发版步骤（照抄）

```bash
# 0) 工作树干净,且就是你要发的那个 commit
git status          # 应无未提交改动
git rev-parse HEAD  # 记下来

# 1) 三机 e2e —— 必须含崩溃恢复(阶段 70)
#    参数是阶段号列表,不是范围:`00 60` 只跑 0 和 6。
set -a && . scripts/e2e/e2e.env && set +a
./scripts/e2e/run.sh 00 10 20 30 40 50 60 70

# 2) 盖戳:把「刚跑过 e2e 的 commit」写进本地文件(不进 git)
./scripts/release/stamp-e2e.sh

# 3) 唯一发版入口:再跑一遍单测,核对戳与 HEAD 一致,再打包
./scripts/release/cut.sh
# 产出: dist/nanotun-YYYYMMDD-HHMMSS-linux-amd64.tar.gz
```

戳文件是 `.release/e2e-stamp`（已 gitignore）。内容必须是**当前 HEAD 的完整 SHA**；
盖戳后又改了代码 / 又 commit 了，必须重跑 e2e 再盖。

## 发版检查单（人工勾）

脚本过了还不够时，发版说明里应能回答：

- [ ] `main` CI 对该 commit 为绿（build-vet + go test）
- [ ] 三机 e2e `00 10 20 30 40 50 60 70` 全绿，戳与 HEAD 一致
- [ ] 若改了 `config.toml` 样例 / systemd unit / install 脚本：在一台干净机上跑过
      `install-self-hosted.sh` 或至少 `nanotun-admin config lint`
- [ ] 发版说明写清：**需要重启才能生效**的配置变更（见下表）
- [ ] 没有引导用户去改**死配置键**（见下表）

## 运维契约（发版说明里必须说清楚的）

### 不用重启

| 操作 | 行为 |
|---|---|
| 用户 PSK 轮换（admin / web） | 立刻写库；约 ≤10s `user_invalidate` 踢旧会话 |
| 禁用/启用用户、平台白名单等 | 同上，周期扫描生效 |
| ACL 等已进 SIGHUP 热更白名单的项 | `systemctl reload nanotun`（`kill -HUP`） |

### 必须 `systemctl restart nanotun`（SIGHUP 只进 deferred）

改了下面任一字段却只 reload：日志会报 deferred，**旧值在重启前仍然有效**
（凭据类还会让「新签的客户端连不上、老客户端一切正常」）。

- `server.listen_addr` / `server.tls_cert_file` / `server.tls_key_file`
- `server.vpn_websocket_path` / `server.control_socket_path`
- `server.upload_rate` / `server.download_rate`
- `server.pow.*`（整段）
- `server.lease_gc_*` / `server.user_invalidate_interval_sec`
- `server.data_plane_ping_*`
- `server.jump_host_firewall` / `server.jump_host_protected_ports`
- `hysteria.listen_addr` / `hysteria.password` / `hysteria.obfs_salamander_password`
- `hysteria.tls_client_ca_file` / `hysteria.udp_relay_enabled`
- `reality.listen_addr`
- `tun.exit_mode` / `tun.exit_dns_redirect` / `tun.exit_deny_private`
- `store.db_path`

权威来源：`cmd/nanotund/reload.go` 的 `classifyDeferredFields`。名单再漏，是安全事故，不是文档疏忽。

### 死配置（能过校验、没有读取点）

保留结构体是为了老 `config.toml` 不致 StrictCheck 全挂。**设了不会生效，也不会提示。**

- `[tcp].*` 整段（含看起来像限速的 `upload_rate` / `download_rate`）—— 限速请用 `[server].*`
- `[kcp].*` 除 `upload_rate` / `download_rate` 外的字段（窗口、crypt、sockbuf 等）均无读取点；
  仅当 `[server]` 未配限速时，`[kcp].upload_rate` / `download_rate` 才作为回退

权威注释：`config/config.go` 里 `KCPConfig` / `TCPConfig`。

## CI 覆盖不到、发版必须补的

| 面 | CI | 发版 |
|---|---|---|
| 无 root 的 `go test` | 阻断 | 再跑一遍（`cut.sh`） |
| `_linux.go` 特权路径（iptables / TUN） | runner 上 Skip | **三机 e2e** |
| SIGHUP deferred / 崩溃自愈 / 出口与 ACL | 无 | **e2e 00–70** |
| `-race` / fuzz | 仅夜间 | 大改动发版前建议手动 `workflow_dispatch` 等一夜 |

## 禁止事项

- 禁止用「我本地随便 go test 过了」代替 `cut.sh`
- 禁止在戳对应的 commit 之外打发布包
- 禁止把测试服口令 / `e2e.env` / `.release/` 打进 git 或发布 tar
- 禁止在发版说明里写「改 PSK 要重启」（用户 PSK 不需要；hy2 `password` 才需要）
