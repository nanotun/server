package util

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
)

// ExitCode 是 nanotund 启动 / 致命错误退出时的语义化 status code。
//
// 背景(2026-05-21 事故关联,G_exit_code):
// 此前所有 logrus.Fatal* 都走 os.Exit(1),systemd journal 只看到 `status=1/FAILURE`,
// 区别「端口被占用」「证书过期」「配置语义错误」「DB 锁不住」要靠人去翻日志正文找
// 关键字 —— 慢、易漏报。给每种致命启动失败安一个 code 后:
//   - 服务端 fatal 日志带 exit_code / exit_code_name 字段,运维 grep / dashboard 关键字
//     直接定位;
//   - systemd 单元用 RestartPreventExitStatus=10 11 20 显式禁止「配置错误」「证书错误」
//     的无脑重启(否则 5 秒后又拉起一遍同样的 fatal,污染日志且掩盖真实问题);
//   - 集成 / e2e 测试可以断言「config 错应得到 10,端口被占应得到 30」,不再只看
//     status=1 一锅端。
//
// 区段约定(每段 10 留给细分):
//
//	0     成功 / OK
//	1     未分类 fatal(保留,过渡期未迁移完的 path)
//	10-19 配置类:解析失败 / 字段冲突 / 必填缺失
//	20-29 TLS 证书 / 密钥
//	30-39 监听 / 端口冲突
//	40-49 数据库 / 存储
//	50-59 backend / 外部依赖
//	60-69 网络栈(iptables / TUN / sysctl)
//	70-79 其它内部错误
//
// 给新场景加 code 时请尽量复用已有区段,不要无脑递增 80+,跨段会让 systemd 单元的
// RestartPreventExitStatus 名单越加越长。
type ExitCode int

const (
	ExitOK             ExitCode = 0
	ExitGeneric        ExitCode = 1
	ExitConfigParse    ExitCode = 10
	ExitConfigSemantic ExitCode = 11
	ExitTLSCert        ExitCode = 20
	ExitListenInUse    ExitCode = 30
	ExitListenOther    ExitCode = 31
	ExitDBInit         ExitCode = 40
	ExitBackend        ExitCode = 50
	ExitNetworkSetup   ExitCode = 60
	ExitInternal       ExitCode = 70
)

// String 给 ExitCode 起一个稳定的英文短名,作为 logrus 字段值方便 grep。
// 名字保持 Pascal,与 const 一致,运维一眼能反查到代码位置。
func (c ExitCode) String() string {
	switch c {
	case ExitOK:
		return "ExitOK"
	case ExitGeneric:
		return "ExitGeneric"
	case ExitConfigParse:
		return "ExitConfigParse"
	case ExitConfigSemantic:
		return "ExitConfigSemantic"
	case ExitTLSCert:
		return "ExitTLSCert"
	case ExitListenInUse:
		return "ExitListenInUse"
	case ExitListenOther:
		return "ExitListenOther"
	case ExitDBInit:
		return "ExitDBInit"
	case ExitBackend:
		return "ExitBackend"
	case ExitNetworkSetup:
		return "ExitNetworkSetup"
	case ExitInternal:
		return "ExitInternal"
	default:
		return "ExitUnknown"
	}
}

// exitFunc 让单测可以替换掉 os.Exit;生产代码不应 touch。
var exitFunc = os.Exit

// FatalExit 打 fatal 级别日志并以指定 code 退出。
//
// 与 logrus.Fatal* 的区别:
//   - 强制带 exit_code / exit_code_name 字段,journal grep 友好;
//   - 用语义化 code 退出而不是 1,systemd 可以按 RestartPreventExitStatus 阻止
//     「配置错 / 证书过期」的死循环重启;
//   - 不跑 defer:与 logrus.Fatal 一致语义,因为本函数只在「无法启动」/「致命异常」
//     路径调用,defer 链(iptables sweep / TUN close)对应「成功启动后再退出」的
//     graceful 路径,在还没装上的状态下跑 sweep 反而清掉别的进程的规则。
func FatalExit(code ExitCode, fields logrus.Fields, format string, args ...any) {
	if fields == nil {
		fields = logrus.Fields{}
	}
	fields["exit_code"] = int(code)
	fields["exit_code_name"] = code.String()
	logrus.WithFields(fields).Errorf(format, args...)
	exitFunc(int(code))
}

// ClassifyListenError 给 listen / Dial 等返回 net.OpError 的场景挑出 EADDRINUSE,
// 让 server.go 用 ExitListenInUse 退出而不是 ExitListenOther。
//
// 之前唯一识别方式是 errors.Is(err, syscall.EADDRINUSE) ——但有些 wrapper(quinn /
// quic-go)会把错误包成自己定义的 typed err 丢掉 syscall 链,这里再用字符串兜底,
// 命中 "address already in use" / "bind: address already in use" 仍按 EADDRINUSE 处理。
// 字符串匹配仅作 fallback,不影响主路径(errors.Is 已经命中时直接返回 true)。
func ClassifyListenError(err error) ExitCode {
	if err == nil {
		return ExitOK
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return ExitListenInUse
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		if errors.Is(opErr.Err, syscall.EADDRINUSE) {
			return ExitListenInUse
		}
	}
	if strings.Contains(strings.ToLower(err.Error()), "address already in use") {
		return ExitListenInUse
	}
	return ExitListenOther
}
