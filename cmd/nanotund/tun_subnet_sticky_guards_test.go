package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/store"
)

// 这里钉两处「静默」:
//
//   - 启动时只读探测上次的 mesh 网段。库不存在 / 打不开 / 表还没建,都必须按「无偏好」处理并继续启动。
//     用可写方式碰它更糟:首次部署时会在真正 Migrate 之前造出一个空库,启动路径从此不确定。
//   - fixed vIP 掉出当前网段的告警。它是运维唯一的线索(数据面照常自动分配,`device list` 却仍显示
//     FIXED_V4=<旧地址>),但每次重连都打一条就会把这条线索埋进日志噪声里 —— 去重和告警本身一样重要。

// TestReadPersistedMeshGateways_TreatsAnUnreadableDBAsNoPreference 探测失败 = 无偏好,且绝不建库。
func TestReadPersistedMeshGateways_TreatsAnUnreadableDBAsNoPreference(t *testing.T) {
	dir := t.TempDir()

	// ① 库还不存在(首次部署)。
	missing := filepath.Join(dir, "not-created-yet.db")
	if got := readPersistedMeshGateways(missing); got != nil {
		t.Fatalf("库不存在时返回了 %v,want nil", got)
	}
	if _, err := os.Stat(missing); err == nil {
		t.Fatal("探测上次网段时把库文件创建出来了 —— 真正的 Migrate 会面对一个「已存在但没有表」的库")
	}

	// ② 路径存在但不是库(被 restore 写坏 / 塞了别的文件)。
	garbage := filepath.Join(dir, "garbage.db")
	if err := os.WriteFile(garbage, bytes.Repeat([]byte("not a sqlite file"), 64), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readPersistedMeshGateways(garbage); got != nil {
		t.Fatalf("库打不开时返回了 %v,want nil —— 探测失败必须退化成无偏好,不能拦住启动", got)
	}

	// ③ 库能打开但表还没建(库被创建过、Migrate 没跑完就断电)。
	empty := filepath.Join(dir, "empty.db")
	st, err := store.Open(context.Background(), empty, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if got := readPersistedMeshGateways(empty); got != nil {
		t.Fatalf("表不存在时返回了 %v,want nil", got)
	}

	// ④ 路径是个目录。
	if got := readPersistedMeshGateways(dir); got != nil {
		t.Errorf("路径是目录时返回了 %v,want nil", got)
	}
}

// countingLogHook 数指定级别的日志条数,用来观察「只告警一次」这类可观测性约束。
type countingLogHook struct {
	mu     sync.Mutex
	msgs   []string
	levels []logrus.Level
}

func (h *countingLogHook) Levels() []logrus.Level { return h.levels }

func (h *countingLogHook) Fire(e *logrus.Entry) error {
	h.mu.Lock()
	h.msgs = append(h.msgs, e.Message)
	h.mu.Unlock()
	return nil
}

func (h *countingLogHook) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.msgs)
}

// TestWarnFixedVIPOutOfMesh_WarnsOncePerPinNotPerReconnect 同一个失效钉住地址只告警一次。
func TestWarnFixedVIPOutOfMesh_WarnsOncePerPinNotPerReconnect(t *testing.T) {
	oldV4, oldV6 := sharedTUNGateway, sharedTUNGatewayV6
	t.Cleanup(func() { sharedTUNGateway, sharedTUNGatewayV6 = oldV4, oldV6 })
	sharedTUNGateway = "10.202.0.1/16"
	sharedTUNGatewayV6 = "fd00:202::1/64"

	// 去重表是包级的,用完清掉,否则会影响别的用例。
	t.Cleanup(func() { fixedVIPWarnOnce = sync.Map{} })
	fixedVIPWarnOnce = sync.Map{}

	hook := &countingLogHook{levels: []logrus.Level{logrus.WarnLevel}}
	logrus.AddHook(hook)
	// logrus 没有 RemoveHook;把等级压到 Panic 让后续用例不受这个 hook 干扰。
	t.Cleanup(func() { hook.mu.Lock(); hook.levels = []logrus.Level{logrus.PanicLevel}; hook.mu.Unlock() })

	stale := &loginAuthResult{Device: &store.Device{
		ID:         7,
		DeviceUUID: "11111111-1111-4111-8111-111111111111",
		FixedVIPv4: "10.9.0.5", // 上一个网段里的地址,当前 mesh 已经换成 10.202/16
	}}

	warnFixedVIPOutOfMesh(stale)
	first := hook.count()
	if first != 1 {
		t.Fatalf("钉住地址掉出网段时告警 %d 条,want 1 —— 运维看到的是「钉了但没用上,且没人说为什么」", first)
	}
	// 同一台设备重连十次(掉线重连、接管都会再走一遍登录)。
	for i := 0; i < 10; i++ {
		warnFixedVIPOutOfMesh(stale)
	}
	if got := hook.count(); got != 1 {
		t.Fatalf("重连 10 次打了 %d 条告警 —— 唯一的线索被自己刷出的噪声埋掉了", got)
	}

	// 换成网段内的地址:一条都不该打。
	fine := &loginAuthResult{Device: &store.Device{ID: 8, FixedVIPv4: "10.202.5.9"}}
	warnFixedVIPOutOfMesh(fine)
	if got := hook.count(); got != 1 {
		t.Errorf("网段内的钉住地址也告警了(累计 %d 条)—— 正常配置被报成异常,运维会去改本来对的东西", got)
	}

	// nil / 无设备的调用不许 panic(未认证会话也会走到这里)。
	warnFixedVIPOutOfMesh(nil)
	warnFixedVIPOutOfMesh(&loginAuthResult{})
}
