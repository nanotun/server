# WSS 数据面应用层 Ping/Pong 协调发布(G_wss_ping)

**状态**:2026-05-22 服务端已落地,默认禁用;启用需协调客户端版本。

## 1. 背景

nanotun 数据面在 wss\://...:8080/internal/nanotun/data-plane/ws/v1/... 上跑链路帧
(LinkType + payload)。之前没有应用层 Ping/Pong,因此:

- 中间盒(运营商 NAT / 公司防火墙)让 TCP 半开时,smux KeepAlive 自己的 ACK 仍能在
  syscall 层返回成功,但实际数据出不去;
- 客户端表面看「smux session still alive」,实际 IP 包写到对端就石沉大海;
- 直到 NAT 完全 RST(5-15min)或服务端检出对端 EOF 才会拆链,用户体感卡顿。

`util.LinkTypePing(6) / LinkTypePong(7)` 自始至终在协议里有定义,但只有 client→server
方向被客户端用了(且服务端只是被动回 Pong)。这次加上 server→client 主动 Ping +
N 次没回 Pong 直接 Close,真正闭环。

## 2. 协议

新增行为(协议帧本身没变):

- **服务端 → 客户端**:每 `data_plane_ping_interval` 发一次 `LinkTypePing`(typ=6)。
  Payload 为 8 字节:`[uint32 seq][4B random nonce]`。
- **客户端 → 服务端**:收到 `LinkTypePing` 必须**原样回显 payload**,以
  `LinkTypePong`(typ=7) 写回。
- **服务端判活**:连续 `data_plane_ping_miss_threshold` 个周期没收到任何 Pong,
  关闭 `linkConn` 触发上层 `cleanupConnection` → 客户端 EOF → 客户端 reconnect。

服务端启动 grace:启动后前 `missThreshold` 次 Ping 不参与判死,留时间给客户端
建链 / handshake 完成。

## 3. 服务端配置

`[server]` section:

```toml
[server]
# G_wss_ping(2026-05-22):数据面 WSS 应用层 keepalive。
# 0 / 缺省 = 禁用(向后兼容老客户端)。
# 推荐 30s + 默认 miss=3 即 90s 无 Pong 判死。
data_plane_ping_interval = "30s"
data_plane_ping_miss_threshold = 3
```

字段:

| 字段 | 类型 | 缺省 | 含义 |
|------|------|-------|------|
| `data_plane_ping_interval` | duration | `0s`(禁用) | server→client Ping 间隔。0 即不启用,行为与历史完全一致。 |
| `data_plane_ping_miss_threshold` | int | `3` | 连续 N 个周期无 Pong 判死。 |

SIGHUP 不会热更新这两个字段(它们影响每条新建 conn 的 keepalive goroutine 启动参数,
改了需 systemctl restart 才会让新连接生效;旧连接保留启动时的值,允许平滑过渡)。

## 4. 客户端要求

- **Go 参考客户端**(`nanotun/client/`):已支持(`client.go:194,448`),
  收到 Ping 立即 WriteLinkFrame(Pong, payload)。
- **Rust 客户端**(`rust_vpn_client_lib`):据 2026-05-21 线上日志 server 收到过
  client→server Ping,说明 Rust 客户端**至少能发** Ping。需要在客户端代码 grep
  确认它也能**响应** server→client 的 Ping。**未确认前不要在生产开启。**
- **iOS / macOS 应用**(苹果客户端):走 Rust client lib,继承其行为。

## 5. 协调发布步骤

1. ✅ 服务端代码合并(本 commit)。默认禁用,无 risk。
2. ⏳ Rust 客户端确认能响应 server→client Ping(grep `LinkTypePing` /
   ping handler in `rust_vpn_client_lib/src/protocol/link.rs` or equivalent)。
3. ⏳ Rust 客户端打 release,iOS/macOS 应用走 TestFlight + 灰度。
4. ⏳ 灰度阶段先在 **测试节点** 把 `data_plane_ping_interval` 设到 `"30s"`,
   monitor `journalctl -u nanotun | grep keepalive` 看「连续 N 次 Ping 无 Pong」
   出现频率。预期:健康客户端 0 触发;不健康客户端在 ≤ 90s 内被踢 + 自动重连。
5. ⏳ 灰度 1 周无异常后推全生产。

## 6. 监控

服务端日志关键字:

- `[keepalive] 数据面 WSS 连续 N 次 Ping 无 Pong,判定僵尸连接,主动 Close`
  → log shipper 关键字告警,频率超过 baseline 视为客户端版本不兼容或网络异常。
- 字段:`remote / conn_id / user_id / last_pong / miss_window / ping_seq`,
  便于按 remote / user 聚合诊断。

## 7. 回滚

直接 `data_plane_ping_interval = "0s"` 或删字段 + SIGHUP**不会**热更新该字段
(见 §3),要 `systemctl restart nanotun.service`。重启会触发 graceful drain
(LinkType=4 Close 902),所有客户端收到通知后正常 reconnect。

## 8. 相关代码

- 服务端发送:`cmd/nanotund/wss_keepalive.go` `startWSSDataPlaneKeepalive`。
- 服务端响应客户端 Ping(老路径):`cmd/nanotund/server.go` `runLinkTunnel` `case util.LinkTypePing`。
- 服务端记录 Pong 时刻:`cmd/nanotund/server.go` `runLinkTunnel` `case util.LinkTypePong`
  (`c.lastPongAtNano.Store`)。
- Connection state:`Connection.lastPongAtNano atomic.Int64`。
- 协议帧:`util/link_frame.go` `LinkTypePing = 6` / `LinkTypePong = 7`。
- 配置字段:`config/config.go` `ServerConfig.DataPlanePingInterval` /
  `DataPlanePingMissThreshold`。
- 单测:`cmd/nanotund/wss_keepalive_test.go`(4 测,覆盖 disabled / healthy /
  never-Pong / Pong-then-stops 四条路径)。
