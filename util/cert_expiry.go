package util

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/sirupsen/logrus"
)

// KeyFilePermMax 是 TLS 私钥文件允许的最宽 Unix 权限位。
//
// 取 0o077 是为了禁止 group / others 任何 r/w/x —— 也就是说 mode & 0o077 == 0
// 才合规。我们不强制必须是 0o600/0o400:0o400 等更紧的也 OK,只要别露给 group/others。
//
// 行为:
//   - mode & 0o077 != 0  → logrus.Warn,但不退出。因为很多容器镜像 / Helm chart
//     默认 fileMode=0o644,运维改不动的话直接 Fatal 反而部署不下去;Warn 让运维看到,
//     同时进程能跑。
//   - root 拥有 -rw-------(0o600) 是标准答案。
//
// 非 Unix(Windows / Plan 9 等)系统直接跳过校验,Go runtime 自己不保证 chmod 语义。
const KeyFilePermMax = 0o077

// CertExpiryWarnWindow 在证书到期前多久开始打 WARN(并不阻止启动)。
// 默认 30 天:与多数 Let's Encrypt / 内部 CA 的续签周期吻合,提前 30 天告警
// 给运维一个充足的续签窗口。
const CertExpiryWarnWindow = 30 * 24 * time.Hour

// LoadAndCheckTLSKeyPair 包装 tls.LoadX509KeyPair,在加载后:
//
//   - 立刻拒绝已过期证书 (NotAfter <= now);
//   - 对即将过期的证书 (NotAfter - now < CertExpiryWarnWindow) 打 WARN 日志。
//
// role 是一个简短标签(如 "hy2" / "vpn-wss" / "hy2-keepalive"),仅用来给运维
// 在日志里区分多份 cert。证书已过期返回 error,调用方应当 Fatal/退出;
// 处于 warn 窗口里仅 logrus.Warn,不影响启动。
//
// 设计原因:之前 server.go、hysteria.go、hysteria_keepalive_ws.go 三处独立
// LoadX509KeyPair,任何一处证书过期都直到 TLS 握手时才报错,且日志分散。
// 统一在启动期 check,运维一眼能看到 "hy2 证书 7 天后过期" 之类的告警。
func LoadAndCheckTLSKeyPair(certPath, keyPath, role string) (tls.Certificate, error) {
	// I9: 加载之前先检查 key 文件权限。warn-but-not-fatal,详见 KeyFilePermMax 注释。
	checkKeyFilePerm(keyPath, role)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("util: load tls keypair %s (%s + %s): %w",
			role, certPath, keyPath, err)
	}
	if len(cert.Certificate) == 0 {
		return cert, fmt.Errorf("util: tls keypair %s has empty Certificate chain", role)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		// Cert 解析失败但 tls.LoadX509KeyPair 已经成功 —— 不阻塞,只 Warn。
		logrus.WithError(err).Warnf("[cert:%s] 解析 leaf 证书失败,跳过到期检查", role)
		return cert, nil
	}
	now := time.Now()
	if !leaf.NotAfter.After(now) {
		return cert, fmt.Errorf("util: tls cert %s 已过期 (NotAfter=%s, now=%s)",
			role, leaf.NotAfter.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	remain := leaf.NotAfter.Sub(now)
	if remain < CertExpiryWarnWindow {
		logrus.WithFields(logrus.Fields{
			"role":      role,
			"not_after": leaf.NotAfter.Format(time.RFC3339),
			"remaining": remain.Round(time.Hour).String(),
			"subject":   leaf.Subject.CommonName,
		}).Warnf("[cert:%s] TLS 证书将在 %s 内过期,请尽快续签", role, remain.Round(time.Hour))
	} else {
		logrus.WithFields(logrus.Fields{
			"role":      role,
			"not_after": leaf.NotAfter.Format(time.RFC3339),
			"remaining": remain.Round(24 * time.Hour).String(),
		}).Infof("[cert:%s] TLS 证书有效", role)
	}
	return cert, nil
}

// checkKeyFilePerm 在 Unix 上检查 keyPath 文件权限,group/others 可读时 Warn。
// 非 Unix 系统直接 noop。
func checkKeyFilePerm(keyPath, role string) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		return
	}
	st, err := os.Stat(keyPath)
	if err != nil {
		// 取不到 stat 不是这层的问题,后面 LoadX509KeyPair 会报真正的 IO 错误。
		return
	}
	mode := st.Mode().Perm()
	if mode&KeyFilePermMax != 0 {
		logrus.WithFields(logrus.Fields{
			"role": role,
			"path": keyPath,
			"mode": fmt.Sprintf("0o%o", mode),
		}).Warnf("[cert:%s] TLS 私钥文件权限过宽(group/others 可读),建议 chmod 600 %s", role, keyPath)
	}
}
