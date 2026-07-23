package main

import "testing"

// TestApplyFlagPrecedence 验证「显式 flag > env > default」的复写逻辑(深扫第十二轮 LOW)。
// 覆盖三条不变量:
//  1. 显式 flag 压过 env(即使 env 也设了同一项);
//  2. 未显式设的 flag 让位给 env;
//  3. 布尔 flag `-no-auto-reload=false` 能强制开启,覆盖 env 的禁用。
func TestApplyFlagPrecedence(t *testing.T) {
	t.Run("explicit_flag_beats_env", func(t *testing.T) {
		t.Setenv("NANOTUN_WEB_LISTEN", "0.0.0.0:1234")
		t.Setenv("NANOTUN_WEB_DB", "/env/db.sqlite")
		t.Setenv("NANOTUN_CONTROL_SOCKET", "/env/control.sock")
		t.Setenv("NANOTUN_WEB_CERT_DIR", "/env/certs")
		t.Setenv("NANOTUN_WEB_TRUSTED_PROXIES", "10.0.0.0/8")

		cfg := defaultConfig()
		setFlags := map[string]bool{
			"listen": true, "db": true, "control-socket": true,
			"cert-dir": true, "trusted-proxies": true,
		}
		applyFlagPrecedence(&cfg, setFlags, flagOverrides{
			listen:         "127.0.0.1:7443",
			db:             "/flag/db.sqlite",
			control:        "/flag/control.sock",
			certDir:        "/flag/certs",
			trustedProxies: "127.0.0.1",
		})

		if cfg.ListenAddr != "127.0.0.1:7443" {
			t.Errorf("listen: flag should win, got %q", cfg.ListenAddr)
		}
		if cfg.DBPath != "/flag/db.sqlite" {
			t.Errorf("db: flag should win, got %q", cfg.DBPath)
		}
		if cfg.ControlSocketPath != "/flag/control.sock" {
			t.Errorf("control-socket: flag should win, got %q", cfg.ControlSocketPath)
		}
		if cfg.CertDir != "/flag/certs" {
			t.Errorf("cert-dir: flag should win, got %q", cfg.CertDir)
		}
		if len(cfg.TrustedProxies) != 1 || cfg.TrustedProxies[0] != "127.0.0.1" {
			t.Errorf("trusted-proxies: flag should win, got %v", cfg.TrustedProxies)
		}
	})

	t.Run("env_wins_when_flag_absent", func(t *testing.T) {
		t.Setenv("NANOTUN_WEB_LISTEN", "0.0.0.0:1234")
		t.Setenv("NANOTUN_WEB_DB", "/env/db.sqlite")

		cfg := defaultConfig()
		// setFlags 为空:没有任何显式 flag,env 应生效。
		applyFlagPrecedence(&cfg, map[string]bool{}, flagOverrides{
			listen: "127.0.0.1:7443", // 快照里有值,但未 set 不应被复写
			db:     "/flag/db.sqlite",
		})

		if cfg.ListenAddr != "0.0.0.0:1234" {
			t.Errorf("listen: env should win when flag absent, got %q", cfg.ListenAddr)
		}
		if cfg.DBPath != "/env/db.sqlite" {
			t.Errorf("db: env should win when flag absent, got %q", cfg.DBPath)
		}
	})

	t.Run("no_auto_reload_false_forces_on_over_env", func(t *testing.T) {
		// env 想禁用自动 reload,但显式 -no-auto-reload=false 应强制开启。
		t.Setenv("NANOTUN_WEB_DISABLE_AUTORELOAD", "true")

		cfg := defaultConfig()
		applyFlagPrecedence(&cfg, map[string]bool{"no-auto-reload": true}, flagOverrides{
			noAutoReload: false, // -no-auto-reload=false
		})
		if !cfg.AutoReloadOnACLChange {
			t.Error("-no-auto-reload=false must force AutoReloadOnACLChange=true even when env disables it")
		}

		// 反向:显式 -no-auto-reload(true)应关闭。
		cfg2 := defaultConfig()
		applyFlagPrecedence(&cfg2, map[string]bool{"no-auto-reload": true}, flagOverrides{
			noAutoReload: true,
		})
		if cfg2.AutoReloadOnACLChange {
			t.Error("-no-auto-reload should disable AutoReloadOnACLChange")
		}
	})

	t.Run("trusted_proxies_explicit_off_clears_env", func(t *testing.T) {
		t.Setenv("NANOTUN_WEB_TRUSTED_PROXIES", "10.0.0.0/8")
		cfg := defaultConfig()
		applyFlagPrecedence(&cfg, map[string]bool{"trusted-proxies": true}, flagOverrides{
			trustedProxies: "off",
		})
		if len(cfg.TrustedProxies) != 0 {
			t.Errorf("-trusted-proxies=off should clear env value, got %v", cfg.TrustedProxies)
		}
	})

	// e_extra_sans:显式 -extra-sans **替换**(而非追加)env 派生的 SAN。
	t.Run("extra_sans_flag_replaces_env", func(t *testing.T) {
		t.Setenv("NANOTUN_WEB_EXTRA_SANS", "env-a.com,env-b.com")
		cfg := defaultConfig()
		applyFlagPrecedence(&cfg, map[string]bool{"extra-sans": true}, flagOverrides{
			extraSANs: "flag-x.com, flag-y.com",
		})
		if len(cfg.ExtraSANs) != 2 || cfg.ExtraSANs[0] != "flag-x.com" || cfg.ExtraSANs[1] != "flag-y.com" {
			t.Errorf("-extra-sans should REPLACE env SANs (not append), got %v", cfg.ExtraSANs)
		}
	})

	// 未设 flag 时保留 env 派生的 SAN。
	t.Run("extra_sans_env_wins_when_flag_absent", func(t *testing.T) {
		t.Setenv("NANOTUN_WEB_EXTRA_SANS", "env-a.com,env-b.com")
		cfg := defaultConfig()
		applyFlagPrecedence(&cfg, map[string]bool{}, flagOverrides{extraSANs: "ignored.com"})
		if len(cfg.ExtraSANs) != 2 || cfg.ExtraSANs[0] != "env-a.com" || cfg.ExtraSANs[1] != "env-b.com" {
			t.Errorf("env SANs should apply when -extra-sans absent, got %v", cfg.ExtraSANs)
		}
	})

	// 显式 -extra-sans=""(空)清空 env 派生项。
	t.Run("extra_sans_explicit_empty_clears_env", func(t *testing.T) {
		t.Setenv("NANOTUN_WEB_EXTRA_SANS", "env-a.com")
		cfg := defaultConfig()
		applyFlagPrecedence(&cfg, map[string]bool{"extra-sans": true}, flagOverrides{extraSANs: ""})
		if len(cfg.ExtraSANs) != 0 {
			t.Errorf("-extra-sans=\"\" should clear env SANs, got %v", cfg.ExtraSANs)
		}
	})
}
