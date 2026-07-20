# 为什么当前实现可能「赶不上」Shadowsocks + Kcptun

## 一、架构对比

| 维度 | Shadowsocks + Kcptun | 当前 nanotun |
|------|----------------------|----------------|
| **数据路径** | 应用 → ss-local(加密) → kcptun-client(KCP) → kcptun-server → ss-server → 公网 | 应用 → TUN → client(smux over KCP) → server → TUN → 公网 |
| **信令** | 无：客户端配置里已有服务器地址和密码，直连 | 有：必须先 WebSocket 登录拿 conv_id / salt / KCP 地址，再建 KCP |
| **首包延迟** | 连本地 → kcptun 直接按配置连远端，无额外 RTT | WS 建连 → 登录 → 收 KCP 配置 → 再建 KCP，多 1～2 个 RTT |
| **端口** | 可单端口（kcptun 一个 UDP），或 SS + KCP 各一个 | 需开放 WS(:8080)、KCP UDP(:3300)；启用 TCP 数据面时另需 **TCP :3401**（默认 `listen_addr`，可改）。云安全组与主机防火墙需一致放行 |

你的**数据**只走 KCP，WS 只做信令，这点和「SS 走 TCP、KCP 只做加速」类似；差异主要在信令和首包、以及下面几项。

---

## 二、可能落后的原因

### 1. 未开 FEC（前向纠错）

- **config.toml** 里：`data_shards = 0`, `parity_shards = 0`，相当于关闭 FEC。
- 在**丢包、抖动大**的链路上，FEC 能明显减少重传、提高有效带宽。
- Kcptun 常用类似 10+3 的 FEC，在弱网下优势明显。

**建议**：在弱网环境打开 FEC，例如：

```toml
data_shards = 10
parity_shards = 3
```

（需确认当前 kcp-go 与 smux 对 FEC 的支持方式，避免与 stream 模式冲突。）

---

### 2. 首包必须多一次「WS 握手」

- 每次建连都要：WS 连接 → 登录 → 收 KCP 配置 → 再建 KCP。
- SS + Kcptun：配置里已有服务器和密码，连本地即等价于「连远端」，没有这层握手。

**建议**（可选）：

- 支持「离线配置」：在客户端配置里直接写 KCP 地址、conv_id、密钥（或派生方式），跳过 WS 或仅用 WS 做可选的心跳/重连，减少首包路径。
- 或至少做「会话复用」：同一进程内多次建隧道时复用已拿到的 KCP 配置，避免每次都重新登录。

---

### 3. KCP 参数只有一套，缺少场景预设

- 当前是单组参数：`nodelay=1, interval=20, resend=2, nc=1, sndwnd/rcvwnd=4096`。
- Kcptun 提供多套预设（fast3 / normal / 等），针对高延迟、高丢包、低延迟等不同场景调优。

**建议**：在配置里增加 2～3 套预设，例如：

- `fast`：低延迟、略高带宽（当前类似）
- `normal`：平衡延迟与丢包
- `weak`：高丢包/高延迟（更大窗口、更激进重传或配合 FEC）

便于用户按网络环境切换，而不是改一堆参数。

---

### 4. 生态与部署形态

- SS：多端客户端、PAC、系统代理、成熟生态。
- 当前：自研客户端 + TUN，需要 root/管理员，且只有一条产品线。

这不是单点「性能」问题，但会让人感觉「用起来不如 SS+kcptun 顺手」。若目标是对齐体验，可考虑：

- 提供 SOCKS5 出口模式（不绑 TUN），方便和现有代理工具、PAC 配合；
- 或明确产品定位为「全隧道 VPN」，在文档里写清与 SS 的取舍（全局 vs 代理）。

---

### 5. 加密与安全

- SS：普遍用 AEAD（如 chacha20-poly1305、aes-256-gcm），算法和实现经过大量审计。
- 当前：KCP 层已有 aes-128 等（`util/kcp_crypt.go`），对很多场景足够；若要对齐「最佳实践」，可考虑默认或可选 aes-256-gcm，并保证密钥只用于加密、不用于认证逻辑。

---

## 三、你已做得不错的地方

- **数据路径不经过 WebSocket**：真实流量只在 KCP 上，延迟和吞吐不会受 WS 拖累。
- **smux 多路复用**：多流复用一个 KCP 会话，和常见 KCP 用法一致。
- **KCP 参数可配置**：nodelay、interval、窗口、MTU、DSCP、SockBuf 等都可调，便于后续做预设。
- **TUN 全隧道**：适合「整机走 VPN」的需求，与 SS 的「代理」定位不同，是互补。

---

## 四、优先可做的改进（按性价比）

1. **在弱网环境开启 FEC**：改 `data_shards` / `parity_shards`，并做一次弱网测试（如 tc 模拟丢包）对比吞吐和延迟。
2. **增加 KCP 预设**：在配置或命令行支持 `mode=fast|normal|weak`，映射到不同 nodelay/interval/window/FEC。
3. **可选「直连 KCP」模式**：配置里允许写死 KCP 地址与密钥时，跳过 WS 登录，减少首包 RTT。
4. **稳定性与可观测性**：在弱网下做长时间跑流 + 断线重连测试，并输出简单指标（如重传率、RTT、断线次数），便于和 kcptun 做对比。

如果你愿意，我可以按你当前 `config.toml` 和 `server.go` 的结构，给出一份具体的 FEC 与预设的修改补丁（含推荐数值和注意事项）。
