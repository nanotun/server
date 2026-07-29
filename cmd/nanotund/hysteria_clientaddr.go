package main

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	hyserver "github.com/apernet/hysteria/core/v2/server"
	"github.com/sirupsen/logrus"
)

// hy2ClientAddrRelay 把 hy2 客户端的**真实地址**送到 Outbound.TCP,从而让环回 smux 上的
// PROXY v2 头携带真实源 —— 服务端的 PoW / 登录限流 / IP 失败计数 / 审计才能按客户端归因。
//
// 为什么需要它:REALITY 的桥接 goroutine 自己持有 realityConn,能直接写真实源(见
// reality_listen.go)。hy2 不行 —— hysteria 的 `Outbound.TCP(reqAddr string)` 不透出客户端
// 地址,共享 smux 池也无法把某条 stream 关联回具体客户端,所以此前 hy2 一律写 LOCAL(无源)头、
// 全部客户端塌到 127.0.0.1。后果不只是审计失真:loginIPLimiter / powIPLimiter 都按 remoteAddr
// 的 host 分桶,于是**所有 hy2 客户端共享同一个桶** —— 单个滥用者就能把全部 hy2 用户一起限死
// (共命运 DoS),而客户端 transport=auto 优先选的正是 hy2。
//
// 怎么做到的(hysteria v2.9.2, server/server.go handleTCPRequest):
//
//	276  putback, err = h.config.RequestHook.TCP(stream, &reqAddr)          ← 可**改写** reqAddr
//	286  h.config.EventLogger.TCPRequest(h.conn.RemoteAddr(), authID, reqAddr) ← 拿到真实地址 + 改写后的 reqAddr
//	290  tConn, err := h.config.Outbound.TCP(reqAddr)                       ← 收到同一个 reqAddr
//
// 三步在**同一 goroutine 内严格顺序**执行,于是:RequestHook 埋一个一次性 token 进 reqAddr →
// EventLogger 按 token 记下真实地址 → Outbound 按 token 取出。token 唯一,故并发客户端之间
// 不会串味,无需 goroutine-local 之类的黑魔法。
//
// 刻意**不**用 TrafficLogger 来做关联:一旦设置 TrafficLogger,hysteria 会把每条 stream 的
// 数据搬运从 copyTwoWay(io.Copy 快路径)切到 copyTwoWayEx(每次 read 都 time.Now()+原子累加+
// 回调),代价压在 hy2 全部流量上,而我们并不需要流量统计。
//
// 安全性:reqAddr 由本 hook 无条件覆盖(Check 对所有 TCP 返回 true),客户端无法注入伪造 token;
// 且 Outbound 依旧完全忽略 reqAddr 的目标语义(只取 token),hy2 不会退化成任意 TCP 开放代理。
type hy2ClientAddrRelay struct {
	mu      sync.Mutex
	pending map[string]hy2PendingAddr
}

type hy2PendingAddr struct {
	addr net.Addr
	at   time.Time
}

const (
	// hy2AddrTokenPrefix 标记「这是本 relay 埋的 token」,与任何真实目标地址都不可能撞。
	hy2AddrTokenPrefix = "nanotun-vpn-stream:"

	// hy2AddrTokenTTL token 从埋入到被 Outbound 取用的存活上限。正常路径是同 goroutine 内
	// 连续三行,微秒级;设 TTL 只为兜住「埋了却never 取用」的异常路径(如 286→290 之间 panic)
	// 不至于让 map 无界增长。
	hy2AddrTokenTTL = 30 * time.Second

	// hy2PendingMax pending 表的硬上限。撞顶时先清过期项,仍满则放弃记录(Outbound 回退
	// LOCAL 头)—— 宁可退回「按环回归因」也不能让内存无界。
	hy2PendingMax = 8192
)

func newHy2ClientAddrRelay() *hy2ClientAddrRelay {
	return &hy2ClientAddrRelay{pending: make(map[string]hy2PendingAddr)}
}

// ---- RequestHook ----

// Check 对所有 TCP 请求返回 true(UDP 不接管)。返回 true 会让 hysteria 走 server-side fast-open:
// 在 dial 出口**之前**就回一个成功的 TCP response。对本服务无碍 —— 我们的 outbound 恒环回本机
// VPN 数据面,客户端读到 response 后紧接着发 VPN1 握手,首包留在 QUIC stream 缓冲里由后续
// copyTwoWay 原样搬运,不丢字节。代价仅是「环回 dial 失败时客户端看到的是握手中断而非
// hysteria 层的错误文案」,属诊断信息降级。
func (r *hy2ClientAddrRelay) Check(isUDP bool, _ string) bool { return !isUDP }

// TCP 把 reqAddr 改写成一次性 token。返回 nil putback:我们不窥探客户端首包(那是 sniff 类
// hook 的用法),让它留在流里由 hysteria 后续原样转发。
func (r *hy2ClientAddrRelay) TCP(_ hyserver.HyStream, reqAddr *string) ([]byte, error) {
	if reqAddr == nil {
		return nil, nil
	}
	*reqAddr = hy2AddrTokenPrefix + newHy2AddrToken()
	return nil, nil
}

// UDP 不接管(Check 对 UDP 返回 false,正常不会走到;DisableUDP 亦已在服务端兜底)。
func (r *hy2ClientAddrRelay) UDP(_ []byte, _ *string) error { return nil }

// ---- EventLogger ----

// TCPRequest 是唯一有实际动作的事件:此时既有真实客户端地址,又有被 hook 改写过的 reqAddr。
func (r *hy2ClientAddrRelay) TCPRequest(addr net.Addr, _ string, reqAddr string) {
	if addr == nil || !strings.HasPrefix(reqAddr, hy2AddrTokenPrefix) {
		return
	}
	r.put(reqAddr, addr)
}

// TCPError:stream 出错/结束。290 行 dial 失败时也会走到这里,顺手把可能残留的 token 清掉,
// 不必等 TTL。
func (r *hy2ClientAddrRelay) TCPError(_ net.Addr, _, reqAddr string, _ error) {
	if strings.HasPrefix(reqAddr, hy2AddrTokenPrefix) {
		r.Take(reqAddr)
	}
}

func (r *hy2ClientAddrRelay) Connect(net.Addr, string, uint64)            {}
func (r *hy2ClientAddrRelay) Disconnect(net.Addr, string, error)          {}
func (r *hy2ClientAddrRelay) UDPRequest(net.Addr, string, uint32, string) {}
func (r *hy2ClientAddrRelay) UDPError(net.Addr, string, uint32, error)    {}

// ---- 供 Outbound 取用 ----

// Take 按 token 取出并**移除**真实地址;取不到返回 nil(调用方回退 LOCAL 头)。
func (r *hy2ClientAddrRelay) Take(reqAddr string) net.Addr {
	if !strings.HasPrefix(reqAddr, hy2AddrTokenPrefix) {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.pending[reqAddr]
	if !ok {
		return nil
	}
	delete(r.pending, reqAddr)
	if time.Since(e.at) > hy2AddrTokenTTL {
		return nil
	}
	return e.addr
}

func (r *hy2ClientAddrRelay) put(token string, addr net.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) >= hy2PendingMax {
		r.gcLocked()
		if len(r.pending) >= hy2PendingMax {
			// 放弃记录而不是无界增长:这条 stream 退回按环回归因,行为等同修复前。
			logrus.WithField("pending", len(r.pending)).
				Warn("[hy2] 真实客户端地址中转表已满,本条 stream 回退环回归因")
			return
		}
	}
	r.pending[token] = hy2PendingAddr{addr: addr, at: time.Now()}
}

func (r *hy2ClientAddrRelay) gcLocked() {
	for k, v := range r.pending {
		if time.Since(v.at) > hy2AddrTokenTTL {
			delete(r.pending, k)
		}
	}
}

// pendingLenForTest 供测试断言 token 不泄漏(不留悬挂条目)。
func (r *hy2ClientAddrRelay) pendingLenForTest() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

// hy2TokenRandRead 是 crypto/rand.Read 的间接层,只为可测性(生产行为不变)。与
// takeoverSecretRandRead 同一手法:熵源故障是唯一走到降级分支的方式,而那条分支的正确性
// (token 仍必须唯一)只能靠注入故障来验证。
var hy2TokenRandRead = rand.Read

// hy2TokenFallbackSeq 给降级 token 兜住唯一性。时间戳单独用是不够的:格式串虽然打到纳秒,
// 但时钟粒度往一微秒上取整(macOS 实测),同一微秒内的两次调用会拿到**同一个** token。
// 撞号的后果正是本文件要修的那件事的反面 —— 两条并发 stream 关联到同一条目,A 的流量按 B 的
// 真实 IP 归因(登录限流 / IP 失败锁定 / 审计全部记到无辜客户端头上)。
var hy2TokenFallbackSeq atomic.Uint64

func newHy2AddrToken() string {
	var b [16]byte
	if _, err := hy2TokenRandRead(b[:]); err != nil {
		// crypto/rand 失败极罕见。退化成「时间戳 + 进程内单调序号」:token 只需在本进程内唯一,
		// 不承担安全语义(客户端无法注入 —— reqAddr 恒被 hook 覆盖)。
		return "t" + time.Now().Format("20060102150405.000000000") +
			"-" + strconv.FormatUint(hy2TokenFallbackSeq.Add(1), 36)
	}
	return hex.EncodeToString(b[:])
}

var (
	_ hyserver.RequestHook = (*hy2ClientAddrRelay)(nil)
	_ hyserver.EventLogger = (*hy2ClientAddrRelay)(nil)
)
