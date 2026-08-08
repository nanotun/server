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

// tlsNotBeforeSkew 是校验证书 NotBefore(生效时间)时容忍的跨机时钟漂移。
// 第十四轮深扫 MED:签发端与本机时钟小幅不同步(或多数 CA 主动回退签发时间几分钟)属常态,
// 留 5min 余量避免刚签发即部署时误判「尚未生效」;超出该余量才在启动期 fail-closed。
const tlsNotBeforeSkew = 5 * time.Minute

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

	cert, leaf, err := loadAndValidateKeyPair(certPath, keyPath, role)
	if err != nil {
		return cert, err
	}
	remain := time.Until(leaf.NotAfter)
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

// ValidateTLSKeyPairFiles 跟上面同一套判据,但不打日志、也不返回证书 —— 给「重启之前
// 先看一眼」的路径用(nanotun-admin config lint)。
//
// 分出来是因为 lint 此前只判文件在不在:一对配不上的证书私钥(拷文件时最常见)、一份
// 被截断的 PEM、一张过期的 Let's Encrypt 证书,统统能拿到 OK。人照着这个绿灯去 restart,
// 服务当场趴下 —— 而 lint 的全部意义就是不让这种事发生。判据只能有一处,散成两份迟早对不上。
func ValidateTLSKeyPairFiles(certPath, keyPath, role string) error {
	_, _, err := loadAndValidateKeyPair(certPath, keyPath, role)
	return err
}

func loadAndValidateKeyPair(certPath, keyPath, role string) (tls.Certificate, *x509.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("util: load tls keypair %s (%s + %s): %w",
			role, certPath, keyPath, err)
	}
	if len(cert.Certificate) == 0 {
		return cert, nil, fmt.Errorf("util: tls keypair %s has empty Certificate chain", role)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		// 第十四轮深扫 MED:此前是「Warn + 返回 cert,nil」→ 跳过有效期检查,等于 fail-open:一份我们**无法解析**
		// 的 leaf(损坏 / 非标准 X.509)会「成功」启动、把错误推迟到 TLS 握手期才炸,且分散难查。既然连 NotBefore/
		// NotAfter 都验不了,就在启动期直接拒(fail-closed),与「空链」「已过期」同等对待。
		return cert, nil, fmt.Errorf("util: tls cert %s parse leaf failed (cannot verify validity): %w", role, err)
	}
	now := time.Now()
	// 第十四轮深扫 MED:除 NotAfter 外也验 NotBefore —— 未生效证书(提前部署 / 时钟偏)此前能「成功」启动,
	// 直到握手才被对端(或自身 verify)拒 → 难排查。启动期一并 fail-closed(留 tlsNotBeforeSkew 容忍小幅漂移)。
	if leaf.NotBefore.After(now.Add(tlsNotBeforeSkew)) {
		// 证书是「未来才生效」的,九成是本机时钟不对而不是证书签错了 —— 新装的 VPS
		// 没跑 NTP、虚拟机从快照恢复,都会把系统时间甩到过去。先看一眼再折腾证书。
		return cert, nil, fmt.Errorf("util: tls cert %s 尚未生效 (NotBefore=%s, now=%s)\n"+
			"  证书要到 NotBefore 才生效,而本机现在停在 now —— 多半是这台机器的时钟不对,\n"+
			"  不是证书签错了。先对时:timedatectl(或 date -u),校准后重启服务。",
			role, leaf.NotBefore.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if !leaf.NotAfter.After(now) {
		// 说清楚下一步。两种来源要分开讲,而且必须点名哪一对**不能**动:profile 里
		// 内嵌的客户端证书是 client-CA 签的,换掉 CA 等于已发出去的二维码全部作废,
		// 而服务器证书这一对重签不影响它们。慌乱中 rm certs/* 是很自然的动作。
		return cert, nil, fmt.Errorf("util: tls cert %s 已过期 (NotAfter=%s, now=%s)\n"+
			"  自带证书(Let's Encrypt 之类)的话:续签后重启服务即可。\n"+
			"  这是装机时自签的那对的话:删掉 %s 与 %s,再跑 nanotun-ensure-assets.sh 重签。\n"+
			"  别顺手删 client-CA(certs/*client-ca*.pem)—— 已发出去的 profile 里的客户端证书\n"+
			"  是它签的,换掉等于所有二维码作废,每个用户都得重发。",
			role, leaf.NotAfter.Format(time.RFC3339), now.Format(time.RFC3339), certPath, keyPath)
	}
	return cert, leaf, nil
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
