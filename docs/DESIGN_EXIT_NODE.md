# Exit Node — 客户端出口节点 Design / 实施计划

让 **客户端机器（Linux / macOS / Windows）也能充当公网出口**，而不只是 server 这一台。
语义对齐 Tailscale exit node：某台客户端声明「我能当出口」，管理员审批后，其它用户
可选择把自己的公网流量经 server 中转到这台出口客户端，由它在本机做 NAT 出公网。

> **架构前提：不做 P2P。** 沿用现有中心化中转：`A → server → 出口客户端 D → 公网`，
> 回程 `公网 → D → server → A`。代价是 server 扛 A↔D 这段双向带宽（v1 接受，metrics 单列 + 带宽帽）。

本特性是 `DESIGN_SUBNET_ROUTES.md`（P2#12）的**数据面落地 + 0/0 特例**：exit = 通告 `0.0.0.0/0`(+`::/0`)
的 approved 子网路由。控制面（subnet_routes 表 / admin route approve / RouteApproveStatus 帧）已存在，
本特性补「允许 0/0（仅 exit 语境）+ 数据面转发 + 出口侧 NAT」。

## 现状回顾

- 数据面入口 `cmd/nanotund/server.go:runLinkTunnel`（type5 IPPacket）：`exitDeniedForPacket` → ACL → `tunWriteChan`（server 自己的 TUN，内核 MASQUERADE 出 WAN）。server 是唯一出口。
- `exit_allowed`（users 表，`Connection.exitAllowed`）= 会话级「能否用出口」闸；与 ACL 正交。
- mesh 互通：TUN 读包按 dst vIP 经 `ip2Channel` demux 投递到对端 `Connection` 的 `VirtualIPAssignment.TunChan`，由 `tunDemuxToLink` 写成 type5 发回客户端。

## 设计决策（v1）

1. **出口表示**：复用 subnet_routes，出口 = device 通告并被 admin 批准的 `0.0.0.0/0` / `::/0`。
2. **出口能力声明**：扩 `RouteAdvertise` 加 `exit bool`；仅当 `exit=true` 时该帧允许携带 0/0/::/0（否则照旧拒 /0，防误声明全网代理）。
3. **使用方选择**：新增 `LinkTypeEgressSelect`（type 19）控制帧，使用客户端运行时选择 `egress = server | <exit device_uuid>`；server 为该会话记 `egressDeviceID` 绑定。
4. **数据面转发**：A 的「dst 非任何 vIP」包，若会话 `egressDeviceID != 0` 且该出口 conn 在线 → 投递到出口 D 的 `TunChan`（而非 `tunWriteChan`）；否则走原 server 自出口。回程由 D 本机 NAT 还原 dst=A 的 vIP，经隧道回 server，按现有 vIP demux 投给 A。
5. **出口侧 NAT（客户端）**：开 ip_forward + 对 mesh 子网来源、dst 非本机 vIP 的流量 masquerade 出物理网卡，回程 rev-NAT 进 TUN。Linux 先行（复用 server `setup-network-and-persist.sh` 配方 / `nanotun-net` nftables 能力）；mac(pf)/Win(WinNAT) 后续。
6. **安全**：admin 审批才生效；`exit_allowed` 仍管「能否用出口」；ACL 可对 exit 流量粒度 deny；出口下线 fail-closed（不静默回落明文）；审计 `route.forward.*`。

## 协议改动（util/）

- `RouteAdvertise` 加 `Exit bool json:"exit,omitempty"`。
- `NormalizeExitAdvertisedCIDR()`：允许 0/0 与 ::/0，其余同 `NormalizeAdvertisedCIDR`。
- `LinkTypeEgressSelect = 19`；`EgressSelect{Schema int, Egress string}`：`Egress` 为空/"server" = 走 server 自出口；否则为出口 device 的 UUIDv4。
- （回程不新增帧：出口客户端做完整 NAT 后回包是普通 type5，dst=请求方 vIP，沿用现有 demux。）

## 服务端改动（cmd/nanotund/）

- `Connection` 加 `egressDeviceID int64`（atomic 或在 linkWrMu 下读写）。
- `route_advertise.go`：`ra.Exit` 时走 exit-aware normalize，允许 0/0/::/0 upsert。
- 新增 `egress_select.go`：处理 type19 帧 → 校验目标 device 是「approved exit」→ 设 `c.egressDeviceID`；回执（复用 RouteApproveStatus 或新增 ack）。
- `approvedExits` 内存快照：`map[deviceID]*Connection`（active 出口 conn），登录/清理/admin approve 时刷新；提供 `lookupExitConn(deviceID)`。
- `runLinkTunnel` type5 分支：`exitDeniedForPacket`/ACL 之后、`tunWriteChan` 之前插入 exit 转发分支（投递到出口 conn 的 TunChan，复用 TunPacket pool 语义）。
- metrics：exitForwarded / exitDroppedNoConn / 带宽计量；audit：`route.forward.applied`。

## Admin CLI（nanotun-admin）

- 复用 `route approve <device> 0.0.0.0/0`；新增便捷 `exit approve/list/revoke`（薄封装）。
- `user create --exit-node-allowed` 可选：限制谁能声明出口（防任意 device 自荐为出口）。

## 客户端改动

- **使用侧**（改动小）：UI 选出口 → 发 EgressSelect → 默认路由 0/0(+::/0) 进自己 TUN（复用现有全局隧道路由）。
- **出口侧**（新增，平台分散）：ip_forward + NAT；Linux 复用 nftables MASQUERADE；mac pf nat anchor；Win WinNAT/RRAS。出口下线 kill-switch。

## 里程碑

- **M1** ✅ 协议 + 控制面（util / store / route_advertise / egress_select / connByDevice / admin）——纯 Go，已单测。
- **M2** ✅ 服务端数据面转发（`forwardPacketToExitNode`）+ metrics；Go 单测 5/5。双 Linux 容器 e2e 脚本见
  客户端仓库的双容器 e2e 脚本。
- **M3** ✅ Linux 出口客户端 NAT（`nanotun-net::exit_nat`，nftables masquerade + ip_forward）+ CLI `--exit-node`/`--exit` 接线。
- **M4** ✅ 使用侧：rust 核心 exit advertise / EgressSelect 发送 + CLI `--exit <device_uuid>`。GUI UI 选择器待接（见 M5-wire）。
- **M5** ✅ 引擎：macOS（pf nat + sysctl 转发）/ Windows（WinNAT）出口 NAT 模块（`src-tauri/src/exit_nat.rs`，纯函数 + 单测）。
  ✅ M5-wire（**三端桌面 GUI 全接通**）：偏好 `exit_node_enabled` / `exit_egress_device`（prefs + Tauri 命令）
  + 前端 `ExitNodeRow`（idle 且非「仅组网」时显示「作为出口」开关 + 出口 UUID 输入）。
  - mac/Win：`vpn_controller::apply_exit_node_intent`（provision 成功后本进程 `exit_nat` 装 NAT + 发控制帧）
    + 各断开路径 teardown。
  - Linux：GUI 偏好经 `nanotun-ipc::ConnectRequest`（新增 `exit_node` / `exit_egress_device`）下发 daemon，
    daemon `run_once` 据此驱动 `nanotun_net::exit_nat` + 发控制帧（复用 CLI 的 M3-wire/M4）。
  - ✅ GUI「掉线自动回落」开关（全平台）：偏好 `exit_fallback_server`（默认关）。mac/Win 在 `vpn_ffi`
    on_debug 识别 `[egress-ack] reason=exit_offline` → 按偏好重发 `EgressSelect{server}` + emit `exit-node-status`
    事件；Linux 经 `ConnectRequest.exit_fallback_server` → daemon。前端 `ExitNodeRow` 在「使用某出口」时显示
    「严格阻断 / 回落服务器」分段开关。
- **DNS 走出口** ✅ 已验证：服务器下发公网 DNS（`8.8.8.8` 等，MagicDNS 关），用出口时 A 的 DNS 查询经隧道→
  出口 D 解析（实测 `api.ipify.org` 经出口 D 解析并 egress = box2 v4/v6）。无需额外代码（公网解析器天然经出口）。
- **M6** 加固（进行中）：
  - ✅ 观测：`/status.exit_node`（含 `forwarded_bytes` / `dropped_rate` / `rate_cap_bps`）+ Prometheus
    `nanotun_egress_select_total` / `nanotun_exit_forward_total` / `nanotun_exit_forward_bytes_total`；
    `exit_node_dataplane_enabled=true`。
  - ✅ 出口下线优雅处理：fail-closed + 一次性 `EgressSelectAck{exit_offline}` 通知客户端（不静默回落明文）。
  - ✅ 带宽帽：`[server].exit_forward_rate_bps`（per-session 出口转发速率上限，0=不限，重启生效）——
    per-session 令牌桶非阻塞 `AllowN`，超额 fail-closed 丢包并计数 `dropped_rate`。
  - ✅ 滥用审计：会话首次经出口转发记一条 INFO（user / conn / exit_device，一次性，换出口复位再记）。
  - ✅ 客户端感知回执：rust 核心读 `EgressSelectAck` 经 `on_debug`（前缀 `EGRESS_ACK_DEBUG_PREFIX`）透出，
    CLI `--exit` 用户始终可见「接受 / 拒绝（将经 server 自出口）/ 中途掉线（fail-closed 阻断）」。
    遵守 fail-closed：核心**不**自动改出口（不静默回落明文），由宿主决定（自动回落需显式开关，留待 UI）。
  - ✅ 掉线自动回落（显式 opt-in）：CLI `--exit-fallback-server`（默认关）——选定出口掉线时主动重发
    `EgressSelect{server}` 回落 server 自出口，避免黑洞；默认仍严格 fail-closed（不静默改出口）。
  - ✅ 宿主 FORWARD 放行加固：出口宿主若 FORWARD policy=drop（ufw/Docker/硬化主机），仅 masquerade 不够
    （转发 NEW 包被 drop，表现「ping 通 curl 不通」）。`exit_nat` 改用 iptables/ip6tables 在宿主 FORWARD 链
    顶部自动插 mesh 子网 ACCEPT（与 WireGuard/Tailscale 同策略），teardown 按记账精确删。
  - ✅ **IPv4 + IPv6 真实公网端到端已验证**：nanotun 203.0.113.10（v6 mesh）+ 出口 box2 203.0.113.20
    （独立公网 v6）。A 经出口 D 的 v4/v6 出口 IP **精确等于 box2 直连 IP、且 ≠ 服务器 IP**，全链路
    `A→server→D→公网` 成立（含 exit_nat 自动放行 FORWARD）。
  - ⏳ 待办：ACL 对 exit 流量粒度。
- **M7** 出口选择器（实时推送，Q1=全局 / Q2=真在跑出口）：
  - **目标**：使用方登录后**无需手填 device UUID**，下拉直接看到「当前在线在跑的出口」，连接中可**实时切换**（EgressSelect 无需重连）。
  - **协议**：新增 `LinkTypeExitsList = 21`（server → client **单向推送**）+ `util.ExitsList{schema, exits:[]ExitInfo{device_uuid, device_name, online}}`。纯推送、无查询帧；老客户端忽略未知帧。
  - **Q2「真在跑出口」**：`Connection.advertisedExit`(atomic)，`route_advertise` 收到带 /0 的 `exit` 帧时置位。
    「可列出的出口」= `advertisedExit ∩ admin approved 0/0|::/0 ∩ 在线`（`buildExitsList`）。
    **`EgressSelect` 同步收紧**：目标会话须 `advertisedExit`，否则拒 `not_running`——堵住「历史 approved 但本次以普通客户端连入、没装 NAT」被选中导致黑洞。
  - **Q1=全局**：任意 `exit_allowed` 用户可见/可用所有在跑出口（单组织语义；多租户后续按 ACL 收紧）。
  - **推送时机**：`exit_allowed` 客户端连上 → `runLinkTunnel` 推初始列表；出口上线（`route_advertise{exit}` 且已 approved）/ 下线（`cleanupConnection` 时 `advertisedExit`）→ `broadcastExitsList` 重算并广播给所有 `exit_allowed` 会话。
    - 已知限制（v1 不做）：server 不监听 DB，**admin 新批准**的出口要等「下一次任意出口上下线 / 客户端重连」才进列表（要即时需补 admin→server control-socket 信号）。
  - **客户端核心**（rust）：读循环收 `LINK_TYPE_EXITS_LIST` → 经 `on_debug`（前缀 `EXITS_LIST_DEBUG_PREFIX` + 紧凑 JSON）透出，宿主解析渲染。纯展示，不改连接行为。
  - **GUI（mac/Win）**：`vpn_ffi` on_debug 缓存快照 + emit `exit-list` 事件；Tauri `get_exit_list`（初始拉）/ `select_exit_live`（记偏好 + 已连接时实时发 EgressSelect）。`ExitNodeRow` 出口下拉来自实时列表（保留手填 UUID 兜底）；出口选择器在 idle 与已连接均可用，「作为出口」开关连接中锁定（需重连）。
  - **Linux GUI**：`get_exit_list`/`select_exit_live` 暂为 None/仅记偏好——出口列表经 daemon IPC 镜像 + 实时选出口待接（紧接的下一步）。
  - ✅ **live e2e 已验证**（真服务器 203.0.113.10 + 两本地容器）：① A 连上初始列表含在跑出口 D；② D 下线后 A 列表移除 D；③ D（预批准）重连后 A 列表恢复含 D。(脚本在客户端仓库)。
    GUI「连接中实时切」= 同一 EgressSelect 帧（转发正确性见 M2/M6 box2 实测），其 click-test 为手动。
  - ✅ Linux GUI 接入（D 架构）：出口列表由 daemon 核心收到 → `LiveState.set_exits_list` → 随 `VpnStateDto.exits_list_json`
    经 GetState/Subscribe 镜像给 GUI；GUI `apply_daemon_state` 去重 emit `exit-list` 事件（与 mac/Win 同事件名，
    前端共用监听）。实时切出口经新 IPC `Request::SelectExitLive` → daemon `singleton::send_egress_select`。
- **M8** 出口身份/地址焊死（出口=基础设施，应稳定）：
  - **动机**：device UUID 是审批 + 客户端 `EgressSelect` 选择的**稳定键**；UUID 一变（重装/无持久卷容器/配置清空），
    出口对所有已选它的客户端「失踪」(saved 选择静默回落 server 自出口)且需重新审批。固定 vIP 给出口稳定地址
    （ACL 例外 / 监控 / 出口上跑服务）。注意：出口数据面**按 device 转发不按 vIP**，故固定 vIP 是基础设施卫生/
    未来留量，UUID 稳定才是必需。
  - ✅ 已有底座：device UUID 客户端落盘稳定（`device_identity` / `/etc/nanotun/device_id`）；服务器 device 级固定 vIP
    （`device.fixed_vip_*`，登录 `preferredLeasedVIPs`: `fixed > 上次 lease > 自动`）+ `device set-fixed-vip`。
  - ✅ **一键指定出口** admin 命令组 `nanotun-admin exit`（把分散步骤焊成原子流程）：
    - `exit designate <device_id> [--v4 IP] [--v6 IP] [--no-vip] [--force]`：upsert+approve `0.0.0.0/0`+`::/0`
      （即便设备尚未 advertise 也可预先焊死）+ 钉死固定 vIP（默认把**当前 lease** 焊死；可指定；无 lease 则告警）。
    - `exit list [--json]`：列出所有出口（有 approved 0/0/::/0 的 device）及固定 vIP。
    - `exit revoke <device_id> [--clear-vip]`：删 0/0+::/0；可选清固定 vIP。
    Go 单测 5 个（designate 自动钉 lease / 显式 vIP / 无 lease 告警 / list / revoke）全绿。
  - ✅ device **预创建**：`nanotun-admin device create <user> --uuid <uuidv4> [--name][--platform]`——先配后连:
    预建已知 UUID 的设备 → `exit designate` 预批准 + 钉 vIP → 把同一 UUID 写进出口机 `/etc/nanotun/device_id`,
    它一连上即为已批准、固定地址的出口。复用 `util.IsValidUUIDv4` + `store.UpsertDevice`(幂等)。单测 3 + 真服务器实跑
    (create→designate→exit list→cleanup)通过。
  - ⏳ 可选后续：出口机 device_id 落持久卷的运维约束文档。
- **M9** 出口选择策略「按授权绑定」（用户拍板的语义）：
  - **原则**：「选了 C」= 绑定 C 这个**已授权**出口。授权(approved)决定绑、在线只决定走/阻断、**唯撤销回退 server**。
    | C 状态 | 处理 |
    |---|---|
    | 已批准 + 在线在跑 | 走 C |
    | 已批准 + 离线/没在跑 | 绑定 C + fail-closed 阻断 + C 回来**自动恢复**（默认）；`exit_fallback_server` 开则回退 server |
    | 被 admin 撤销 | 回退 server + 响亮通知 |
    | `not_running`（在线没跑出口） | 当「暂时不可用」=绑定+等它跑（同离线） |
  - **Phase 1 ✅（选择按授权绑定）**：`handleEgressSelectFrame` 改用 `resolveApprovedExitDeviceID`（按 UUID 在 approved 出口集解析 deviceID，**在线/离线均可**）→ 解析到即绑、解析不到（撤销/未知）→ `egressDeviceID=0`+`not_approved`（回退 server）。`forwardPacketToExitNode` 成功投递复位 `exitOfflineNotified`（per-episode 通知 + 自动恢复）。单测 + 实跑验证（选离线 approved→accepted/绑定；选未批→not_approved/server）。
  - **Phase 2 ✅（撤销实时 + 新批准即时推送）**：`egressDeviceID` 改 `atomic.Int64`；control endpoint `POST /reload?what=exits` → `revalidateExitBindings`（绑定设备被撤销→CAS 重置回 server + `EgressSelectAck{revoked}` 通知）+ `broadcastExitsList`。admin `exit designate/revoke`、`route approve/reject/delete`(出口) 后 best-effort `notifyExitsChanged`。实跑验证：A 用着 C、`exit revoke C` → ~3s A 收到 revoked + 改经 server（不重连）。
  - **Phase 3**：
    - **E ✅ 出口偏好 per-profile**：`exit_egress_device` 从全局移到 `profile_store.StoredProfile`（各 server 各记各的）；连接按当前 profile 取（`resolve_active_exit_egress`）；选出口写当前 profile，仅当前连接的 profile 才实时切。
    - **F ✅ 撤销客户端提示**：CLI/GUI 对 `reason=revoked` 显示「已被管理员撤销，已自动改经 server」。
    - **D ✅ 实测为非问题（strict-block 零泄露窗口）**：理论上连接瞬间约 1RTT 内首包可能经 server 自出口。
      用真出口机 box2(203.0.113.20，真 NAT) 实测:A `--kill-switch --exit box2` 连接,从发起即密集采样公网出口 IP →
      序列为 `1×BLOCKED(连上前 kill-switch 阻断) → 20×box2(203.0.113.20)`,**全程无一次 server IP(203.0.113.10)**。
      即:kill-switch 挡住连上前流量 + `EgressSelect` 在首个出口包之前就绑定 → **实践中无可观测泄露**。
      故**不做** D 的多端连接时序重排(改连接关键路径有风险、收益为零)。若将来真观测到泄露再议。
  - **完整转发 live e2e ✅（真出口机 box2）**：A(本地容器,full-tunnel `--exit box2`)→ server(203.0.113.10)→ D(box2,真 NAT)→ 公网。
    实测:① A 出口 IP = box2(203.0.113.20);② box2 下线 → A fail-closed 阻断(出口 IP 空,非 server);③ box2 上线 → A 自动恢复经 box2(不重连);
    ④ `exit revoke` box2 → ~5s A 实时改经 server 自出口(203.0.113.10)+ 收到 `reason=revoked`(不重连)。P1/P2/P3-E 全链路成立。
  - **深扫加固（第三轮 Bugbot + 逻辑复核）✅**：
    - **DB 出错不误伤绑定**：`deviceHasApprovedExitRoute` / `resolveApprovedExitDeviceID` 返 `ok` 位，区分「DB 查不动(无法判定)」与「确实未批准」。`revalidateExitBindings`：`keep = approved || !ok`，DB 抖动**绝不误撤销**在用出口；`handleEgressSelectFrame`：`!ok` 回 `try_again`（不改现状、不静默回落 server），仅 `deviceID==0`(确认未批) 才 `not_approved` 回退 server；`buildExitsList` / 广播：DB 查不动时保守「不列 / 不广播」。取舍：真撤销若恰逢 DB 故障会延后到下次 `revalidate` 成功——这是「绝不误撤销」优先级换来的。
    - **出口列表仅连接时镜像（客户端 Linux GUI）**：`apply_daemon_state` 仅 `Connected` 镜像 `exits_list_json`、其余清 `None`，修重连过渡期 daemon DTO 残留把陈旧/离线出口灌回刚清空的下拉。
    - **`try_again` 客户端提示**：mac/Win(`vpn_ffi`) + CLI/daemon(`connect.rs`) 新增 `reason=try_again` 分支（server DB 暂时无法确认出口资格 → 出口**未变**、提示重试），不落进 generic「将经 server 自出口」误导。
    - **`advertisedExit` 清除收窄（push 前深扫抓到的 high，已修）**：仅「空 advertise 撤回 / 断开」清（确定信号），**非出口 / 增量帧不动**。因客户端 `send_exit_advertise` 连上只发一次 `{exit,[0/0,::/0]}`、停止做出口靠空撤回或断开表达；早先「无 /0 即清」会误踢「仍在跑出口、后续只发增量/子网帧」的会话 → 黑洞。
    - 验证：server `-race` 全套（含回归 `TestRevalidateExitBindings_DBErrorKeepsBinding`：关 store 造 DB 错 → 绑定保持、不回 `revoked`）+ 三端编译（mac/Linux `src-tauri`、Linux `nanotun-cli`）+ tsc + 修后两仓 Bugbot clean，已推送。
  - **深扫加固（第四轮 全特性逻辑审计）✅**：
    - **热切换不丢出口绑定（HIGH 泄露）**：`handleTakeoverLogin` 的 `newConn` 继承 `egressDeviceID` + `advertisedExit`。reality→hy2 热切换(takeover)原本不过户这两个出口会话态 → ① 选了出口的使用方静默改经 server 自出口(泄露);② 出口节点自己热切换后从下拉消失 + 绑它的会话被 fail-closed。takeover 既是「换链路保身份」,出口态应同 vIP/exitAllowed/deviceID 一样过户;客户端 lib 内热切换(`promote_to`)只发 takeover LoginReq、**不重发** RouteAdvertise/EgressSelect,只能服务端继承。
    - **出口状态事件接入前端 + Linux 闭环（#3）**：`exit-node-status`(exit_offline/revoked/try_again/accepted/rejected)此前只发不收 → 撤销时 server 已回落 server 但 GUI 仍显示选着失效出口。前端(`MainPage`)监听:撤销/拒绝响亮提示 + 清本地出口选择(回 server、下次不再重试);掉线/暂不可确认仅提示。Linux 经 daemon DTO `exit_node_status` 透传(`serve`/`connect`/`vpn.rs`),与 mac/Win `vpn_ffi` emit 同口径、前端共用监听。
    - **自选出口口径一致（#4）**：`EgressSelect` 选到自己 → 显式回退 server + `reason=self`,消除「ack=accepted 却实际走 server」。
    - **初始列表不漏推（#5）**：`pushInitialExitsList` 改用 `context.Background()`,不随「连上瞬断」取消 tunCtx 而漏首推（`buildExitsList` 自带 5s 超时）。
  - **深扫加固（第五轮）✅**：
    - **A 出口状态重连重放（med）**：daemon 的 `exit_node_status` 仅被 `set_disconnected` 清,自动重连(`set_reconnecting`/`set_connecting`)不清 → 重连/GUI 重启把上次会话的 `revoked`/`offline` 当**新事件重放**(误弹横幅 + 冗余清选择)。修:`set_connected` 在「已连接」转换点复位 `exit_node_status=None`,只承载当前会话回执(本会话 `EgressSelectAck` 必在 `set_connected` 之后才到,不会误抹);`exits_list_json` **不**在此复位(靠服务端重连 `pushInitialExitsList` 自愈,复位反有「推送早于 `set_connected`」抹空风险)。
    - **B 撤销撞接管窄竞态（low）**：takeover 落定后若 `newConn` 继承了出口绑定,异步补一次 `revalidateExitBindings` —— 防撤销侧 revalidate 只扫到尚未 takenOver 的 oldConn、CAS 落在已死 oldConn 而漏掉 newConn。幂等不误撤销;仅 `egressDeviceID!=0` 才触发。极窄(撤销须撞 ms 级接管窗口),与「DB 故障撤销延迟」同类。
    - **C 出口广播写阻塞（low，既有非本次引入）**：`sendExitsListTo` 钉 5s 写超时(对齐 `user_invalidate`/`tunDemux`),避免一个卡死的 `exit_allowed` 客户端(TCP 窗口满)持 `exitsBroadcastMu` 拖住**所有**出口列表广播与初始推送。
    - 验证：server `-race` 全套 + 三端编译 + tsc + lint。

## 风险 / 取舍

- 中转双倍带宽（无 P2P 的代价）。
- 0/0 安全门：必须 admin 明确批准 + 数据面只转发被授权 exit 流量，避免开放代理。
- 出口客户端 IP 成为他人出口：需同意 + 审计 + 限速（法务/滥用）。
