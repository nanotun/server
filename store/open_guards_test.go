package store

// open_guards_test.go:Open / Close 的失败路径,以及 server_dial_host 里几条只有
// 直接调用才能到的守卫。
//
// Open 的失败必须是「开不出来就报错」,而不是「开出一个半残的 Store 让上层慢慢撞」——
// 后者在部署现场表现为一连串看不出根因的 "no such table",运维会一直往错的方向查。

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resolvedIPs(ips ...string) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(ips))
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out
}

func TestOpen_FailsLoudlyInsteadOfHandingBackAHalfBrokenStore(t *testing.T) {
	ctx := t.Context()

	t.Run("空路径", func(t *testing.T) {
		if s, err := Open(ctx, "", Options{}); err == nil {
			_ = s.Close()
			t.Fatal("空路径应被拒 —— 否则会在当前工作目录里随手建一个库")
		}
	})

	t.Run("父目录建不出来", func(t *testing.T) {
		// 把一个普通文件当成目录用:MkdirAll 必然失败。
		blocker := filepath.Join(t.TempDir(), "iam-a-file")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if s, err := Open(ctx, filepath.Join(blocker, "sub", "x.db"), Options{}); err == nil {
			_ = s.Close()
			t.Fatal("父目录建不出来却开成功了")
		}
	})

	t.Run("路径是个目录", func(t *testing.T) {
		dir := t.TempDir()
		if s, err := Open(ctx, dir, Options{}); err == nil {
			_ = s.Close()
			t.Fatal("把目录当库文件却开成功了")
		}
	})

	t.Run("文件不是数据库", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "garbage.db")
		if err := os.WriteFile(path, []byte(strings.Repeat("这不是 sqlite 文件", 100)), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if s, err := Open(ctx, path, Options{}); err == nil {
			_ = s.Close()
			t.Fatal("拿一堆垃圾当库却开成功了 —— --db-path 打错字时应当立刻报错")
		}
	})

	t.Run("内存库可用且不落文件", func(t *testing.T) {
		s, err := Open(ctx, ":memory:", Options{})
		if err != nil {
			t.Fatalf("Open :memory:: %v", err)
		}
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("内存库上迁移: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})

	t.Run("nil store 上 Close 不 panic", func(t *testing.T) {
		var s *Store
		if err := s.Close(); err != nil {
			t.Fatalf("nil store Close: %v", err)
		}
	})
}

func TestServerDialHost_SetterAndValidatorEdges(t *testing.T) {
	ctx := t.Context()

	t.Run("超长值连 setter 都不该收", func(t *testing.T) {
		// 校验器本来就会拦,这里是 DAL 的第二道:任何绕过 handler / CLI 直接调 setter
		// 的路径(未来的 SDK / 脚本)也不能把超过 RFC 1035 上限的值塞进库,
		// 客户端拿到它塞进 PacketTunnel 会直接把隧道搞挂。
		s := newTestStore(t)
		long := strings.Repeat("a", 254)
		if err := s.SetServerDialHost(ctx, long); err == nil {
			t.Fatal("254 字节的 host 应被拒")
		}
		if v, err := s.GetServerDialHost(ctx); err != nil || v != "" {
			t.Fatalf("被拒的值落库了: %q err=%v", v, err)
		}
	})

	t.Run("读故障不能伪装成「未配置」", func(t *testing.T) {
		// 空串的语义是「没配」,调用方会据此 fail-fast 让 admin 去设置页填。
		// 把一次读故障也返回空串,运维会以为自己没填过,填完还是坏的。
		dead := newDeadStore(t)
		if v, err := dead.GetServerDialHost(ctx); err == nil {
			t.Fatalf("v=%q err=nil,库都关了", v)
		}
	})

	t.Run("hostname 语法诊断", func(t *testing.T) {
		// 这几条只有直接调才到:外层 ValidateServerDialHost 会先把空串放行、
		// 把超长挡掉,轮不到内层再判一次。内层的保险栏仍要有效,因为它也被
		// 别的调用点复用。
		if err := validateRFC1035Hostname(""); err == nil {
			t.Fatal("空 hostname 应被拒")
		}
		if err := validateRFC1035Hostname(strings.Repeat("a", 254)); err == nil {
			t.Fatal("超长 hostname 应被拒")
		}
		if err := ValidateServerDialHost(strings.Repeat("a", 64) + ".example.com"); err == nil {
			t.Fatal("单个 label 超过 63 字节应被拒 —— DNS 根本不接受这种 label")
		}
	})

	t.Run("干净的解析结果放行", func(t *testing.T) {
		if err := CheckResolvedDialIPs("vpn.example.com", nil); err != nil {
			t.Fatalf("空列表: %v", err)
		}
		if err := CheckResolvedDialIPs("vpn.example.com", resolvedIPs("203.0.113.10", "2001:db8::1")); err != nil {
			t.Fatalf("公网地址应当放行: %v", err)
		}
	})

	t.Run("解析到危险段一律拒", func(t *testing.T) {
		for _, ip := range []string{"127.0.0.1", "0.0.0.0", "169.254.1.1", "224.0.0.1", "255.255.255.255", "::1", "ff02::1"} {
			err := CheckResolvedDialIPs("vpn.example.com", resolvedIPs(ip))
			if err == nil {
				t.Fatalf("解析到 %s 却放行了 —— DNS 投毒或内网 resolver 会让客户端拨到自己身上", ip)
			}
			if !errors.Is(err, ErrServerDialHostDNS) {
				t.Fatalf("ip=%s err=%v,想要能被 errors.Is 认出的 DNS sentinel", ip, err)
			}
		}
	})

	t.Run("探活时上层取消不该报成地址有问题", func(t *testing.T) {
		// admin 关掉页面 / 服务重启时,ctx 会被取消。把它当成「域名解析失败」
		// 会给出一条 400 + 审计,让人以为地址填错了。
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		err := ProbeServerDialHost(cancelled, "vpn.example.com")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v,想要 context.Canceled", err)
		}
		if errors.Is(err, ErrServerDialHostDNS) {
			t.Fatal("取消被归类成 DNS 失败了")
		}
	})

	t.Run("pinger 初始化失败算软错", func(t *testing.T) {
		// 软错的意思是:界面上给 admin 一个「跳过 ICMP 检测」的选项,而不是拒绝保存。
		// 云厂商默认封 ICMP 太常见,硬拒会让合法地址存不进去。
		err := pingOnce(ctx, "")
		if err == nil {
			t.Fatal("空目标应当报错")
		}
		if !errors.Is(err, ErrServerDialHostICMPSoftFail) {
			t.Fatalf("err=%v,想要 ICMP 软错 sentinel —— 硬错会把合法地址挡在外面", err)
		}
	})
}
