package main

// credentials_flash.go(2026-05-26 / P1#2):
//
// 「PSK 一次性展示」走经典 PRG(Post-Redirect-Get)流程,而不是 POST handler 直接
// 渲染结果页 —— 后者只要 admin 误按浏览器刷新 / 后退就会**重新触发 POST**(浏览器
// 默认会弹「确认重新提交表单」对话框,但很多人不看就点确定),结果是创建路径
// 重新建一个用户、reset-psk 路径再 rotate 一次 PSK。前者会让一行 admin 误操作
// 在 audit 里多出一行无意义的 user_create / user_reset_psk;后者更糟 —— 用户拿到
// 的旧 PSK 立刻失效,而 admin 一个无操作的页面刷新就能让你客户端被踢下。
//
// 仓库已有的 flash 机制只是 URL query string ?flash=text(handler_dashboard.go 等),
// 适合「已删除用户 X」这种纯文案,**无法**承载 PNG bytes / 完整 nanotun-cred:// URL,
// 也没有「一次性消费」语义(直接在 URL 里 → 任何人能转发链接复看)。
//
// 这里实现一个最小内存 flash store:
//   - key 是 256-bit crypto/rand token(base64url, 43 字符);
//   - value 是任意 Go struct(本仓库内只用 *credentialsFlashPayload,但 store
//     不绑定具体类型,未来其它一次性页面可以复用同一个 store);
//   - TTL 5 min,GC goroutine 每分钟 prune 一次;
//   - **一次性消费**:Pop 命中即从 map 删,后续重复 GET 拿不到 → 模板分支
//     fall-through 到「已过期」提示。
//
// 不引入第三方 session/flash 库:
//   - 现有 cookie / session 已经够轻;
//   - 内存 store 在「单实例 nanotun-web」部署模型下没问题(本仓库没在用 ha-pair
//     方案;web 进程重启把所有 pending flash 一并丢掉也是可接受的语义 —— admin
//     重启进程时本来也不该有「半中断」的 PSK 展示页);
//   - 不引第三方 session 库免得 supply chain 多一层 attack surface,审计简单。

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"html/template"
	"sync"
	"time"
)

// credentialsFlashTTL 控制 token 在内存里的最大存活时间。
//
// 5 分钟来源:admin 走完「create / reset-psk → 看到结果页 → 把 QR 发给同事 / 抄
// PSK」典型链路一般 30s 内完成;5 分钟给「页面被打断 / admin 临时去开会」留余量,
// 但又短到「敏感 payload 不会长时间漂浮在内存里」。这是一次性凭证 ≠ session。
const credentialsFlashTTL = 5 * time.Minute

// credentialsFlashTokenBytes:256-bit crypto/rand,与 web session id / CSRF token
// 同等强度,确保即便 attacker 暴力枚举 URL 也找不到合法 token。
const credentialsFlashTokenBytes = 32

// credentialsFlashKind 用来区分「user 创建」与「reset-psk」两种结果页;同一个
// store 复用时 GET handler 才能选模板。也防止 token 复制后被用错路径(虽然
// 概率很低,但一旦 admin 误把 user_created token 拼到 reset-psk URL 上,
// 至少 GET handler 能 reject 而不是渲染半正确内容)。
type credentialsFlashKind string

const (
	credentialsFlashKindUserCreated  credentialsFlashKind = "user_created"
	credentialsFlashKindUserResetPSK credentialsFlashKind = "user_reset_psk"
)

// credentialsFlashPayload 是一次性结果页要展示的全部字段。
//
// 字段全部值类型(string / int64 / template.URL),GC 友好且不持有后端句柄。
// 不放原始 *store.User 指针 —— RotateUserPSK 后再读一次拿到 freshU 已足够,
// 多存指针只会绑住生命周期,不增加信息。
type credentialsFlashPayload struct {
	Kind        credentialsFlashKind
	UserID      int64
	Username    string
	PSK         string
	CredID      string
	CredCreated string
	CredURL     string
	CredQRImage template.URL

	// 2026-05-26 wire 扩展:credentials QR 携带 server 标识。模板把这俩字段显示给
	// admin 看(`对应服务器: <Host>`),让"多服务器场景下把一堆 QR 攒到一起分不清"
	// 这个痛点消失。
	//
	//   Host     = app_settings.advertised_host(空字符串 = server 未配 advertised_host;
	//              caller 已经 read 失败 fallback "")
	//   ServerID = app_settings.server_id(UUID;模板不展示,只为 audit / debug 留)
	Host     string
	ServerID string
}

// credentialsFlashEntry 是 store 内部记录,external 不可见。
type credentialsFlashEntry struct {
	payload credentialsFlashPayload
	expires time.Time
}

// credentialsFlashStore 是进程内一次性 token → payload 映射。
//
// 锁选择:sync.Mutex + map。Pop 是 read+delete 复合操作,sync.Map 不支持
// 原子的「读完即删」,需要 LoadAndDelete + 手动 fallback;直接 Mutex 写起来
// 更可读。预期并发不高(admin 串行操作居多),性能不是瓶颈。
type credentialsFlashStore struct {
	mu      sync.Mutex
	entries map[string]credentialsFlashEntry
}

// newCredentialsFlashStore 构造一个空 store 并启动后台 GC goroutine。
//
// stop chan 由 caller 控制(典型 main.go 在 ctx.Done 时关闭),GC goroutine
// 在 stop 关掉后退出,不在测试中泄漏。
func newCredentialsFlashStore(stop <-chan struct{}) *credentialsFlashStore {
	s := &credentialsFlashStore{entries: map[string]credentialsFlashEntry{}}
	go s.runGC(stop)
	return s
}

// runGC:每分钟扫一次 map,删过期 entry。频率不高,锁持有时间短。
func (s *credentialsFlashStore) runGC(stop <-chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.prune(time.Now())
		}
	}
}

func (s *credentialsFlashStore) prune(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.entries {
		if now.After(v.expires) {
			delete(s.entries, k)
		}
	}
}

// Stash 写入一条 payload 并返回 token。失败返回错误(crypto/rand 故障)。
//
// 写完即可在 Location: ?token=<token> 里 redirect。
func (s *credentialsFlashStore) Stash(p credentialsFlashPayload) (string, error) {
	tok, err := flashGenerateToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.entries[tok] = credentialsFlashEntry{
		payload: p,
		expires: time.Now().Add(credentialsFlashTTL),
	}
	s.mu.Unlock()
	return tok, nil
}

// errCredentialsFlashMissing:token 不存在 / 已过期 / 已被消费过。
//
// GET handler 看到这个错误就渲染「凭证展示已过期或失效」提示,不让 admin
// 通过反复刷新 URL 持续看到 PSK。
var errCredentialsFlashMissing = errors.New("credentials flash: token missing or expired")

// Pop 拿出 payload 并立即从 map 删。kind 不匹配也视作 missing(防止
// reset-psk URL 拼到 user_created 路径之类的混淆攻击)。
func (s *credentialsFlashStore) Pop(token string, kind credentialsFlashKind) (credentialsFlashPayload, error) {
	if token == "" {
		return credentialsFlashPayload{}, errCredentialsFlashMissing
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[token]
	if !ok {
		return credentialsFlashPayload{}, errCredentialsFlashMissing
	}
	if time.Now().After(entry.expires) {
		delete(s.entries, token)
		return credentialsFlashPayload{}, errCredentialsFlashMissing
	}
	if entry.payload.Kind != kind {
		// **第三轮深扫 P2·安全收紧**:kind 不匹配的合法路径不存在(每个 POST handler
		// 写入时 kind 固定,redirect URL 也对应固定的 GET path)→ 不匹配 = referrer
		// 泄漏后的枚举 / 拼接攻击。此时立刻删除该 entry,避免攻击者继续试 kind 值。
		// 副作用:若 token 真的被误拼,合法路径下次访问会显示「已过期」,这就是预期。
		delete(s.entries, token)
		return credentialsFlashPayload{}, errCredentialsFlashMissing
	}
	delete(s.entries, token)
	return entry.payload, nil
}

// Len 给测试 / 监控用,返回当前未消费 entry 数。
func (s *credentialsFlashStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func flashGenerateToken() (string, error) {
	buf := make([]byte, credentialsFlashTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
