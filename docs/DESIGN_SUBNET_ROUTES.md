# Subnet Route Advertise — Design (P2#12)

本文档描述 nanotun 的「子网路由声明 + 管理员审批」机制的**控制平面** —— 协议、存储、admin CLI。

> **数据面进展**：服务器侧数据面(server 把流量真正转发到宣告方 device、宣告方本机 NAT 进 LAN、请求方装路由)
> **已落地**。SR-M1(服务器转发 + 已批准子网路由表,见 `cmd/nanotund/subnet_route.go`)已生效:`route approve`
> 的非 0/0 CIDR 在宣告方在线且 ACL 放行时会真正承载流量;SR-M2 指宣告方客户端把该流量 NAT 进其 LAN 的那一段。
> 下文 §3「数据面(本期未实现)」/ §5「客户端实现要点」是当初控制面阶段的接入设想,实际实现以代码为准。

## 1. 背景

nanotun 默认只解决「用户 → 用户」组网:每个 device 拿到一个 vIP,peers 之间
通过 server 中转(项目走中心化组网,不做 P2P 直连)。但很多场景下,某台 device 同时还连着内网
办公网/家庭 NAS,运维希望:
- 该 device 把 `192.168.1.0/24` 广播出去,声明「我能 forward 这段流量」;
- 其它 mesh peers 想访问 `192.168.1.50` 时,server 把对应 IP 包发给那台
  广播 device,由该 device 通过它本机的 routing 表去触达内网;
- 管理员显式批准每条路由,避免任何 device 私自把别的子网拉进 mesh。

这与 Tailscale 的 `--advertise-routes` / `--accept-routes` 语义对齐,但本文
只描述 server 与协议侧,客户端实现单独排期。

## 2. 协议

新增两个 LinkType(见 `util/link_frame.go`):

| LinkType | 方向 | 名字 | body |
| -------- | ---- | ---- | ---- |
| 15 | client → server | `LinkTypeRouteAdvertise` | `util.RouteAdvertise` JSON |
| 16 | server → client | `LinkTypeRouteApproveStatus` | `util.RouteApproveStatus` JSON |

JSON 形态:

```json
// 15 client → server
{"schema": 1, "routes": ["192.168.1.0/24", "10.20.0.0/16"]}

// 16 server → client
{
  "schema": 1,
  "updated": [
    {"cidr":"192.168.1.0/24","status":"approved","at":1716391200},
    {"cidr":"10.20.0.0/16","status":"rejected","reason":"私网冲突","at":1716391300}
  ]
}
```

### 行为约定

1. **客户端何时上报**:登录成功之后任意时刻;最常见在客户端启动 + 一段时间
   广播一次,以应对网卡变化。**空 `routes` 列表表示撤回所有 pending 声明**
   (server 不会回退已 approved 的条目)。
2. **服务端何时回 status**:每收到一帧 advertise 都会回一帧 status,只包含
   本帧 advertise 涉及的 CIDR;另外 server 在登录或重连后**主动 push 一帧
   全量 snapshot**(client 拿来初始化 UI)。该全量 push 在数据面落地阶段再
   补,本期 control 阶段只保证「ad-hoc reply」一定有。
3. **schema 必须等于当前版本** (`util.RouteSchemaCurrent`,目前 = 1)。schema
   不兼容变更要 bump 数字,server / client 各自负责拒绝旧版本。
4. **路由数量上限**:单帧最多 64 条(`server.RouteAdvertiseMaxRoutes`),超
   出会被 server 静默截断 + Warn log。
5. **CIDR 必须可解析、不能是 /0**:server 端在落库前调用
   `util.NormalizeAdvertisedCIDR()`:
   - 拒绝 `0.0.0.0/0`、`::/0` 等"全网代理"声明;
   - 把 `192.168.1.5/24` 之类带主机位的写法 mask 化为 `192.168.1.0/24`。
6. **不允许匿名 device 声明路由**:客户端登录时必须给出合法 RFC4122v4
   `device_uuid`,否则 server 直接拒绝整帧(`routeAdvAnonymous` 计数自增)。

## 3. Server 端实现

### 存储

`store/migrations/0006_subnet_routes.sql`(schema_version = 6):

```sql
CREATE TABLE subnet_routes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    cidr          TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'pending',
    advertised_at INTEGER NOT NULL DEFAULT 0,
    approved_at   INTEGER NOT NULL DEFAULT 0,
    reason        TEXT    NOT NULL DEFAULT '',
    UNIQUE(device_id, cidr)
);
```

CRUD 走 `store/subnet_routes.go`,核心语义:

- `UpsertAdvertisedRoute`:不存在 → 新建 pending;存在 → 仅更新
  `advertised_at`,**不**重置 status。这条**很关键** —— 客户端短暂掉线再
  连不会回退 approved 状态。
- `DeleteAdvertisedRoutesForDevice`:只删 pending,保留 approved/rejected。
- `SetRouteStatus(device, cidr, status, reason)`:admin 路径调用;reason
  只在 rejected 状态下保留。

### 数据面(本期未实现)

未来 server 在 IP 包入口的判断顺序:

1. **vIP fast-path**:dst 命中 vipOwner → 直接 demux 到对应 conn。
2. **subnet route 命中**:dst 不在 vipOwner 但匹配某 approved CIDR →
   找该 CIDR 对应 device 的 active conn,封包 demux 过去。多 device
   广播同一 CIDR 时按 "最近 advertised + active" 优先,这里要落地一个
   in-memory `approvedRoutes` snapshot,SIGHUP / admin approve 时刷新。
3. **公网出口**:走 `exit_allowed` + iptables(已有 `[tun].exit_mode`)。

落地这一段时,要把已有的 `aclDropPacketDirected` / `exitDeniedForPacket`
顺序前置,并扩 ACL 规则让运营能对 subnet route 流量做粒度 deny。

### Control 与 Stats

- `/status` JSON 新增:
  ```json
  "route_advertise": {
    "accepted": 12, "rejected": 1, "anonymous": 0, "failed": 0
  }
  ```
- 不专门新增 audit 类型 —— admin 改状态走 store,审计走 admin 自己;
  数据面接入后再加 `route.forward.applied` 系列 audit 类型。

## 4. Admin CLI

`nanotun-admin`:

```bash
# 列出全部 / 按设备 / 按用户 / 按状态过滤
nanotun-admin route list
nanotun-admin route list --device 12
nanotun-admin route list --user alice
nanotun-admin route list --status pending

# 审批
nanotun-admin route approve 12 192.168.1.0/24
nanotun-admin route reject  12 10.0.0.0/8 --reason "冲突"

# 物理删除
nanotun-admin route delete  12 192.168.1.0/24
```

`route list / show` 走只读连接(`query_only` pragma),其它子命令走写连接。

## 5. 客户端实现要点(后续 milestone)

留给客户端组的待办,本期仅在协议侧把"洞"留好:

1. 用户在客户端 UI 上勾选要广播的 CIDR(或读 `--advertise-routes` 命令行
   参数);
2. 登录成功后 send 一帧 `LinkTypeRouteAdvertise`;
3. 监听 `LinkTypeRouteApproveStatus`,把 pending/approved/rejected 渲染到
   UI;rejected 弹出 `reason`;
4. 接收对端流量后,客户端要在系统路由表上把对应 vIP 当作 gateway 注入
   (Linux:`ip route add 192.168.1.0/24 dev tun0`);
5. 收到非自己 vIP 的 packet 时,通过本机 routing(IP forward)转发到真实
   内网。客户端要做 NAT(IP masquerade)避免对端目标看到 vIP source。

## 5.5 与 `exit_mode = "isolate"` 互斥

子网路由是「经宣告方这台**客户端**中转进 LAN」，回程（宣告方 → server → 请求方 vIP）走普通
mesh 投递、要过内核 FORWARD，而 isolate 在那里装的正是 `-i <tun> -o <tun> DROP` —— 于是审批
照常成功、客户端照常装上路由、流量 100% 黑洞。三机实测（2026-07-25）：isolate 下已批准的
`192.168.88.0/24` 请求全超时，服务器 DROP 计数器同步上涨。

现在的处置：启动期若 `exit_mode=isolate` 且库里存在已批准的出口设备 / 子网路由，打一条 WARN
（`cmd/nanotund/isolate_relay_warn.go`），提示要么改 `exit_mode = "mesh"`，要么把这些审批清掉，
免得客户端装上黑洞路由（若与它本地真实 LAN 前缀重叠，还会连带打断本地访问）。

## 5.6 撤销审批曾被「同一台宣告方当出口节点」绕过（2026-07-25 修复）

三机实测发现的审批闸绕过。复现路径：C 宣告并被批准 `192.168.88.0/24`（其后方 LAN 用 netns 模拟，
**只有 C 能到**，server 自己路由不过去，故穿透是真的）；A 经子网路由正常访问；随后 admin
`route delete` 撤销审批。

撤销后 server 侧看起来是对的：已批准表重建为 `routes=0`，A 的 `ip route` 里那条 `192.168.88.0/24
dev nanotun0` 也被撤下了。但 A 是**全隧道**客户端、出口选的正是 C，于是同一个目的地落进默认路由，
被当作**普通公网流量**转发给 C；而 C 上为该网段装的 `FORWARD ACCEPT` + `MASQUERADE` 并没有随撤销
拆除，照样投递进 LAN。抓包为证：`nanotun0 In 10.201.0.77 > 192.168.88.10` →
`veth-c Out 192.168.88.1 > 192.168.88.10`（已 NAT）→ 回程原路返回，内容照常拿到。

根因在 `forwardPacketToExitNode`：那里原有一道 confused-deputy 守卫会丢弃「目的落在**已批准**子网
路由前缀内」的包（那不是公网流量）。审批一撤，`lookupSubnetRoute` 不再命中，同一个目的地就从
「内部，丢弃」**翻转**成「公网，转发给出口」—— 语义正好和撤销相反。于是「谁能进 C 的内网」实际上
由 C 本机残留的防火墙规则决定，而不是 admin 的审批闸。

修法：peer 出口只承载**公网**流量，私网 / 链路本地目的地一律不转发给它
（`privateDstDeniedForPeerExit`，计数 `exit_node.dropped_private_dst`）。档位复用
`tun.exit_deny_private`（`auto` 拦 RFC1918 + CGNAT + ULA + 链路本地；`link-local` 只拦链路本地，
含云元数据那一条；`off` 关掉）。mesh 自身地址不受影响：调用点前面已被 `isLocalMeshDst` /
`isMeshCIDRAddr` / `is4via6` / `lookupSubnetRoute` 逐一排除。实测修复后：已撤销网段被拒、
从未宣告的网段被拒、重新批准后合法访问立即恢复，公网 / mesh / MagicDNS 均无影响。

**宣告方为何不随撤销拆规则**（有意为之，不是漏掉）：客户端按 `--advertise-routes` 在**声明之前**
先把 NAT/转发装好（见客户端 `exit_nat::apply` 处注释：装成功才向 server 声明），这样审批永远不会
跑在数据面前面。若改成「撤销即拆、重新批准再装」，就会引入「server 已批准、客户端还没装好」的窗口
—— 正是这个顺序要避免的黑洞。故闸门放在 server 侧是正确且充分的；宣告方的规则只表达「这台机器被
配置成愿意为该网段做路由器」，在 server 不投递该网段流量时不可达。

## 5.7 4via6 曾被反源欺骗守卫整条打死（2026-07-25 修复）

三机实测：A 经 4via6 访问 C 后方内网，MagicDNS 正确返回 `fdbc:4a60::2:c0a8:580a`（site 2 +
`c0a8:580a` = 192.168.88.10），A 也装上了 `fdbc:4a60::/64 dev nanotun0`，server 侧
`subnet_route.forwarded` 正常上涨且各类丢弃计数全为 0，C 的用户态转发器（`via6_only`）也确实把请求
解码后投进了内网、内网主机也回了包 —— 但 `ping6` 100% 丢包、TCP 全超时，**一个包都回不来**。

根因在 `connSourceSpoofed` 的反源欺骗守卫：它把 `is4via6(src)` 无条件判为伪造，理由是「合法中继回程源
只会是外网 / LAN 地址或对端 vIP」。这个前提对 4via6 恰好不成立 —— 请求方连的就是
`fdbc:4a60::<site>:<v4>`，宣告方的回包**只有以该地址为源**才能匹配上请求方的连接（客户端 netstack
正是这么回的）。于是回程在 server 被计成 `src_spoof_drops`（ICMP + TCP 各试一轮，计数 +31）。

修法：4via6 源不再一律判伪造，收窄成「该 site ID 映射到**本会话自己的 device**，且内嵌 v4 落在本
device **已被 admin 批准**的宣告网段内」（`via6SrcOwnedByConn`）。与纯子网中继的收窄同一口径：既放通
合法回程，又不让一个宣告方拿别人 site 的地址（冒充另一站点的内网主机）或自己 pending / 已撤销网段的
地址当源向 mesh 对端注包。site 表 / 已批准表未加载时不收窄，避免启动与 reload 瞬态误杀。

修复后实测：4via6 的 TCP 与 ICMP 均端到端可达；别人 site、未批准网段、未知 site、普通会话拿 4via6
当源仍判伪造（单测覆盖）。

> ICMP 经 4via6 能通是因为客户端另有一条 ICMP echo 中继（真 ping 目标、可达才合成 EchoReply 注回），
> 与 netstack 的 `enable_icmp(false)` 不冲突 —— 后者关的是「接口本地伪造 EchoReply」那种假通。

## 5.8 链路本地曾可作子网路由宣告 → 跨用户冒充云元数据（2026-07-26 修复）

`advertisableSubnetRanges` 白名单里原本明确列着 `169.254.0.0/16`（IPv4 link-local）与 `fe80::/10`，
与出口侧的判断直接矛盾 —— `exit_guard.go` 把 169.254/16 列为「**无条件**拦」，理由正是「169.254.169.254
一条就等于把服务器的云身份（IMDS 的 IAM 凭证 / 服务账号 token）交给每个 VPN 用户」。

三机实测复现（危害不需要任何服务器漏洞，只需一次疏忽审批）：

1. A（user `testcli`）宣告 `169.254.169.254/32` —— 旧白名单放行（`32 >= 16`），落成 pending；
2. admin `route approve 1 169.254.169.254/32`（看着只是个无害的保留段，工具也不给任何提示）；
3. C（user `u4`，`--accept-routes`）装上 `169.254.169.254 dev nanotun0`，**metric 0，压过 DHCP 装的
   `metric 100` 那条**；
4. C 请求 `http://169.254.169.254/v1.json` 拿到的是 A 身后主机伪造的内容，C 自己真实的云元数据
   （`instanceid`）反而不可达。

即：任一可宣告的客户端 + 一次审批 = 对全 mesh 所有 `--accept-routes` 客户端**跨用户冒充云元数据服务**。

修法：把链路本地从白名单移除（v4/v6 都移）。链路本地按定义逐链路、不可路由，「我身后有一个
169.254 / fe80 网段」没有合法语义；真要访问对端链路本地资源应走 4via6 或具体的 RFC1918 编址。
存量已批准条目无需删库 —— `rebuildSubnetRouteTable` 载入时用 `PrefixWithinAdvertisable` 复核同一门槛，
移除后自动被挡在转发表外。错误信息里点明「link-local is NOT advertisable」及其原因。

顺带：宣告网段若与 server 自身 mesh 网段（TUN CIDR）交叠，现在在 `handleRouteAdvertiseFrame` 就地拒绝、
不再写 pending。此前它会被收下（实测客户端宣告 `10.201.0.0/16` = mesh 网段本身，服务器照收成 pending），
数据面早有 `meshPrefixOverlaps` 挡着所以永不生效 —— 但 admin 能 approve 并看到「approved」，
这个「批了却永远不通」的状态纯属误导。

## 6. Open questions

- ~~重复 CIDR 的优先级仲裁~~（**已闭环**，2026-07-26）：数据面本就有确定性 tiebreak ——
  `lookupSubnetRoute` 最长前缀优先、**同长度取最小 deviceID**（深扫#14），消除切片 / DB 行序带来的
  不确定，语义无需再定。剩下的 UX 缺口已补：`route approve` 现在在「同一 CIDR 已批给别的设备」时
  告警（`route.duplicateCIDR`，只告警不阻断 —— 为计划中的路由器替换而并存一段时间是合理操作）。

  三机实测确认了 tiebreak 与它的危害形态：C（device 31）已批准 `192.168.88.0/24` 且身后真有主机；
  让 A（device 1）也宣告同一 CIDR 并批准后，仲裁归 **A**（1 < 31），而 A 身后并没有这个网段 →
  该网段**整体失联**（`curl 192.168.88.10` 超时），C 的 LAN 成了不可达的死重 —— 这正是告警要拦住
  的误操作。同时验证：**4via6 不受仲裁影响** —— `192-168-88-10via2.lan` 显式带 site ID（site 2 = C），
  照旧直达 C 身后主机，因为 4via6 本就是「点名某个宣告方」的消歧机制。
- 路由声明 audit / 告警:首版 `route_advertise` 计数器够用;若 reject
  率高需要更细的 audit 类型(`route.reject.applied`)。
- 安全:目前仅在登录路径要求合法 `device_uuid`,没有"路由声明权"per-user
  开关。可考虑在 users 表加 `routes_allowed bool`,disable 后客户端 advertise
  会被 server 直接拒并通过 status 帧告知(`reason: "user disabled for routes"`)。
