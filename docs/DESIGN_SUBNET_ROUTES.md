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

## 6. Open questions

- 重复 CIDR(两台 device 都声明 `192.168.1.0/24`)的优先级仲裁:
  现在 store 只保证 UNIQUE(device_id, cidr),不约束跨 device。落地数据面
  时需要在 admin CLI 加 `--exclusive` flag,或在 server 内存 snapshot
  里按 `approved_at desc` / round-robin 选 device。
- 路由声明 audit / 告警:首版 `route_advertise` 计数器够用;若 reject
  率高需要更细的 audit 类型(`route.reject.applied`)。
- 安全:目前仅在登录路径要求合法 `device_uuid`,没有"路由声明权"per-user
  开关。可考虑在 users 表加 `routes_allowed bool`,disable 后客户端 advertise
  会被 server 直接拒并通过 status 帧告知(`reason: "user disabled for routes"`)。
