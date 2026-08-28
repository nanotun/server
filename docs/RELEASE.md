# 发布流程（硬门禁）

这份文档是**唯一**允许的发版路径。合并到 `main` 不等于可以发版；对外发出任何东西
之前必须过完下面的门。

三机 e2e 跑不进 GitHub Actions（要 root、要真机、要测试服口令），所以 CI 绿只覆盖
**合并**门槛；**发版**门槛由本仓库脚本强制，不能靠记性。

## 两道门

| 门 | 拦住什么 | 怎么过 |
|---|---|---|
| **合并门**（CI） | 编译坏了、格式漂了、单测红了 | `go build` / `vet` / `gofmt` / `go test ./...` / e2e selftest |
| **发版门**（本机 + 三机） | 「CI 绿但真机行为没验」就发版 | `scripts/release/cut.sh vX.Y.Z`：单测 + **与 HEAD 对齐的 e2e 戳** + 打包 + 打 tag |

直接跑 `scripts/build-release.sh` **会被拒绝**，除非设了
`NANOTUN_RELEASE_I_KNOW=1`（调试用；发出版本包不要用）。

## 门禁怎么传到 CI

三机 e2e 在本地跑，产物却由 GitHub Actions 构建 —— 中间靠 **annotated tag** 把
「已过门」这件事带过去：

1. `cut.sh` 校验 e2e 戳与 HEAD 一致后，打一个 annotated tag，
   message 里写 `e2e-stamp=<40 位 SHA>`；
2. 推送 tag 触发 `.github/workflows/release.yml`；
3. workflow 的 `verify-tag` job 做三条**机器校验**，任一不过就拒绝发布：
   - tag 必须是 annotated（lightweight tag 直接判死——那是绕过门禁最容易的路子）
   - tag message 里的 `e2e-stamp` 必须等于 tag 指向的 commit
   - 该 commit 必须在 `origin/main` 上

所以**手工 `git tag` 推上去是发不出版本的**，只能走 `cut.sh`。

## 发版步骤（照抄）

```bash
# 0) 工作树干净,且就是你要发的那个 commit
git status          # 应无未提交改动
git rev-parse HEAD  # 记下来

# 1) 先把 HEAD 装到 SRV 上 —— 漏了这步,e2e 验的是上一个版本的服务端
#    脚本顺带把 e2e.env 里的 E2E_EXPECT_VERSION 改成同一个 dev-<sha>,并回读校验。
#    (阶段 0 那条版本断言就是在兜这个底,但它要跑到 e2e 中途才报,前面全白跑。)
./scripts/e2e/deploy-srv.sh

# 2) 三机 e2e —— 必须含崩溃恢复(阶段 70)
#    参数是阶段号列表,不是范围:`00 60` 只跑 0 和 6。
set -a && . scripts/e2e/e2e.env && set +a
./scripts/e2e/run.sh 00 10 20 30 40 50 60 70

#    配了调度机的话改用 run-remote.sh:同样的断言,27 分钟而不是 47 分钟(差的全是
#    网络往返,详见 scripts/e2e/README.md)。它会强制把调度机对齐到本地 HEAD,
#    否则戳会盖在一个「没跑过 e2e」的 commit 上,而戳里只有一个 SHA,事后查不出来。
./scripts/e2e/run-remote.sh 00 10 20 30 40 50 60 70

# 3) 盖戳:把「刚跑过 e2e 的 commit」写进本地文件(不进 git)
#    配了调度机时它会自己去读那一轮的退出码(last-run.rc),非 0 直接拒绝盖戳。
#    别用日志末尾那句「合计 …,失败 0」判断过没过 —— 环境塌掉的那一轮长得一模一样
#    (断言没跑成只记 ENV、不计失败),唯一的区别就是退出码 2。
./scripts/release/stamp-e2e.sh

# 4) 唯一发版入口:再跑一遍单测,核对戳与 HEAD 一致,打包,打 tag
./scripts/release/cut.sh v0.1.0
# 本地产出: dist/nanotun-v0.1.0-linux-{amd64,arm64}.tar.gz + SHA256SUMS
# 同时建好 tag v0.1.0(**不会自动推送**)

# 5) 对照下面的检查单,确认后推 tag —— 这一步才真正对外发布
git push origin v0.1.0
```

推完 tag 后 GitHub Actions 会构建并发布：

- **GitHub Release**：`nanotun-vX.Y.Z-linux-{amd64,arm64}.tar.gz` + `SHA256SUMS`
- **GHCR 镜像**：`ghcr.io/nanotun/server:{X.Y.Z, X.Y, latest}`（多架构 + 构建溯源）

注意两边的版本号**差一个 `v`**：tarball 是 `v1.0.0`，镜像是 `1.0.0`（容器生态的
惯例，metadata-action 默认剥掉前缀）。照抄 Release 页面的版本号去 pull 会拿到
`not found`，而那句话看着像没权限或镜像是私有的。

`dist/` 里本地打的那份从此只是**自检产物**，不要手工上传 —— 对外分发的一律以 CI
构建的为准（本地产物依赖维护者那台机器的环境，别人复现不了）。

版本号格式钉死 `vX.Y.Z` 或 `vX.Y.Z-rcN`。rc 版只推精确的镜像 tag，**不动 `latest`
和 `X.Y`** —— 否则所有 `docker pull ...:latest` 的用户会被悄悄升到预发布版上。

戳文件是 `.release/e2e-stamp`（已 gitignore）。内容必须是**当前 HEAD 的完整 SHA**；
盖戳后又改了代码 / 又 commit 了，必须重跑 e2e 再盖。

反悔：tag 推出去之前 `git tag -d vX.Y.Z` 即可。**推出去之后别删** —— 已经有人可能
拉过那个镜像了；发一个 `vX.Y.Z+1` 覆盖它。

## 发版检查单（推 tag 之前人工勾）

脚本过了还不够时，发版说明里应能回答：

- [ ] `main` CI 对该 commit 为绿（build-vet + go test + docker 镜像双架构构建）
- [ ] 三机 e2e `00 10 20 30 40 50 60 70` 全绿，戳与 HEAD 一致
- [ ] 若改了 `config.toml` 样例 / systemd unit / install 脚本：在一台干净机上跑过
      `install-self-hosted.sh` 或至少 `nanotun-admin config lint`
- [ ] 发版说明写清：**需要重启才能生效**的配置变更（见下表）
- [ ] 没有引导用户去改**死配置键**（见下表）
- [ ] 版本号符合 semver 语义：破坏性变更进 major / minor，别塞进 patch

推完 tag 后还要人工确认一次：

- [ ] Actions 里 `Release` workflow 三个 job 全绿
- [ ] Release 页面上 amd64 / arm64 两个 tar 和 `SHA256SUMS` 都在
- [ ] `docker pull ghcr.io/nanotun/server:X.Y.Z` 在一台干净机上能拉能起

**首次发版专有**：GHCR 上新建的包默认是 private，要去仓库 Packages 页手动改成
public，否则用户 `docker pull` 会被要求登录。这一步 workflow 做不到。

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
- `tun.forward_block_bt` / `tun.forward_block_tracker_6969` / `tun.forward_block_smtp_25`
- `tun.tcp_connlimit_per_ip` / `tun.udp_connlimit_per_ip`
- `store.db_path`

最后那两行尤其容易漏，而漏掉的代价是**安全策略没生效却毫无提示**：把
`tcp_connlimit_per_ip` 从 40 收到 5、SIGHUP、日志一切正常，于是以为收紧了，实际旧的
iptables 规则还在（`reload.go:454` 那段注释记的就是这次）。封堵类的 `forward_block_*`
同理：改了不重启，等于没封。

权威来源：`cmd/nanotund/reload.go` —— `classifyDeferredFields` 只覆盖最常改的那几个，
完整判据是该文件里所有登记为 deferred 的字段（`reload_deferred_guards_test.go` 盯着它们）。
本表比单个函数宽，是因为它还收了「函数不报、但同样要重启」的那些。名单再漏，是安全事故，
不是文档疏忽。

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
- 禁止手工 `git tag` 后直接推（CI 的 `verify-tag` 会拒，但别去试探它）
- 禁止把 `dist/` 里本地打的 tar 手工传到 Release 页 —— 对外产物一律由 CI 出
- 禁止删除已推送的 tag / 已发布的镜像 tag（用户可能已经拉过了，发新版本覆盖）
- 禁止把测试服口令 / `e2e.env` / `.release/` 打进 git 或发布 tar
- 禁止在发版说明里写「改 PSK 要重启」（用户 PSK 不需要；hy2 `password` 才需要）
