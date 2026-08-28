package main

import (
	"strings"
	"testing"

	"github.com/nanotun/server/config"
)

// PoW 自适应难度是登录侧唯一「按 IP 累进」的防爆破闸门,而它的形状由五个旋钮共同决定:
// failures_enable(何时开始 ramp)、base(平时)、ramp(跳档起点)、step(每次失败加成)、ceiling(封顶)。
//
// 这一族此前只有「难度不越出协议窗口」的守卫,**曲线形状本身没有任何断言** —— 于是
// failures_enable 漏了零值默认替换这件事藏了很久:取 0 时 `failures < failuresEnable` 恒假,
// 永远走 ramp 分支,base_difficulty 完全不可达,整条曲线向上错位一档。参考部署与线上都没有
// [server.pow] 段(全零),所以这就是**所有部署的实际行为**:
//
//	错位后  failures=0→14, 1→16, 2→18, 3→20, 4→22(封顶)
//	设计值  failures=0→8,  3→14, 4→16, 5→18, 6→20, 7+→22
//
// 两个后果都不会报错、不会断连,所以没人会去查:每次正常登录多付 64 倍哈希(8→14 bit);
// 而**普通用户连输错 4 次密码就撞上 22-bit 封顶**(注释自己写的是「~10s 客户端 / iPhone 15s」),
// 设计上要 7 次才到那里。
//
// 曲线是「安全强度」与「正常用户成本」的分界线,所以必须逐点钉住,而不是只钉边界。

// TestComputeDifficulty_DefaultCurveMatchesTheDocumentedTable 不配 [server.pow] 时,
// 曲线必须与 ComputeDifficulty 文档里那张表逐点一致。
//
// 用「全零构造」而不是直接塞字段:要验的正是**零值 → 默认**这一步。直接塞 failuresEnable=3
// 会把本轮修的那个缺陷整个跳过去。
func TestComputeDifficulty_DefaultCurveMatchesTheDocumentedTable(t *testing.T) {
	svc, err := NewPoWService(nil, nil, 0, 0, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("全零配置(= 没有 [server.pow] 段)必须能构造出服务: %v", err)
	}

	// 先钉生效值本身:曲线错了先看是哪个旋钮没落到默认。
	if got := svc.failuresEnable; got != config.PoWDefaultFailuresEnable {
		t.Errorf("failuresEnable 生效值 = %d,期望默认 %d —— 取 0 会让 base_difficulty 永不可达",
			got, config.PoWDefaultFailuresEnable)
	}

	for _, tc := range []struct{ failures, want int }{
		{0, 8},  // 平时:一次没失败,必须是 base,不是 ramp
		{1, 8},  // 阈值以下仍是 base
		{2, 8},  // 阈值以下最后一档
		{3, 14}, // 恰好到阈值:跳 ramp 起点(step*0)
		{4, 16},
		{5, 18},
		{6, 20},
		{7, 22},  // 封顶
		{8, 22},  // 封顶后不再涨
		{99, 22}, // 远超也不越顶
	} {
		if got := svc.ComputeDifficulty(tc.failures); got != tc.want {
			t.Errorf("默认配置 failures=%d → 难度 %d,期望 %d", tc.failures, got, tc.want)
		}
	}
}

// TestComputeDifficulty_FailuresEnableOneRampsFromTheFirstFailure
// 「第 1 次失败就 ramp」这个诉求在 0 变成「未配」之后仍然表达得出来 —— 写 1。
//
// 这一条是上面那个修法的**前提**:如果 0 改成默认之后这个语义就没法表达了,那修法本身就是个回归。
func TestComputeDifficulty_FailuresEnableOneRampsFromTheFirstFailure(t *testing.T) {
	svc, err := NewPoWService(nil, nil, 1, 0, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("failures_enable=1 是合法配置: %v", err)
	}
	if got := svc.ComputeDifficulty(0); got != 8 {
		t.Errorf("failures_enable=1 时没失败过仍应是 base 8,得到 %d", got)
	}
	if got := svc.ComputeDifficulty(1); got != 14 {
		t.Errorf("failures_enable=1 时第 1 次失败就该进 ramp 14,得到 %d", got)
	}
}

// TestComputeDifficulty_HonoursExplicitKnobs 显式配置的五个旋钮都要真的被用上。
//
// 每个旋钮各取一个「与默认不同」的值,并让期望值只能由该旋钮解释 —— 否则某个旋钮被忽略时
// 曲线仍可能凑巧对上默认曲线,而那正是死配置的典型样子(本轮 base_difficulty 就是这么死的)。
//
// ceiling 取 17 是**承重的**,不是随手挑的数:默认 adaptive_ceiling 恰好等于协议上限
// PoWMaxDifficulty(都是 22),于是默认配置下那条封顶钳位被协议钳位完全遮蔽 —— 把
// `d > adaptiveCeiling` 整段删掉,默认曲线一点变化都没有(实测变异只被本用例抓到)。
// 只有让 ceiling 严格小于协议上限,才验得到它自己那一行。
func TestComputeDifficulty_HonoursExplicitKnobs(t *testing.T) {
	// failures_enable=2, base=6, ramp=10, step=3, ceiling=17
	svc, err := NewPoWService(nil, nil, 2, 6, 10, 3, 17, 0)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	for _, tc := range []struct {
		failures, want int
		why            string
	}{
		{0, 6, "阈值以下用 base=6(不是默认 8)"},
		{1, 6, "阈值以下用 base=6"},
		{2, 10, "到阈值 2 跳 ramp=10(不是默认 14)"},
		{3, 13, "每次失败 +step=3(不是默认 2)"},
		{4, 16, "继续 +3"},
		{5, 17, "被 ceiling=17 截住(而非 10+3*3=19)"},
		{9, 17, "远超仍是 ceiling=17(不是默认 22)"},
	} {
		if got := svc.ComputeDifficulty(tc.failures); got != tc.want {
			t.Errorf("failures=%d → %d,期望 %d(%s)", tc.failures, got, tc.want, tc.why)
		}
	}
}

// TestComputeDifficulty_NegativeFailuresAreTreatedAsZero 失败次数为负按 0 算。
//
// 计数来自滑窗表,理论上不会为负;钉它是因为一旦为负,`failures < failuresEnable` 会成立、
// 落到 base —— 也就是说负数会静默变成「最低难度」,方向恰好是不安全的那一侧。
func TestComputeDifficulty_NegativeFailuresAreTreatedAsZero(t *testing.T) {
	svc, err := NewPoWService(nil, nil, 0, 0, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := svc.ComputeDifficulty(-5), svc.ComputeDifficulty(0); got != want {
		t.Errorf("failures=-5 → %d,应与 failures=0 的 %d 一致", got, want)
	}
}

// TestPoWConfig_ResolveMatchesWhatNewPoWServiceActuallyUses
// config 侧的 Resolve* 与 NewPoWService 真正落进结构体的值必须一致。
//
// 两边一旦漂移,reload 的「生效值比较」就会按一套值判断、而在跑的服务按另一套跑:
// 要么把等价改写误报成 deferred(噪声),要么把真改动判成没变(漏报)。而这一族默认值
// 原本就是因为「只存在于 NewPoWService 内部」才漏掉了 failures_enable。
func TestPoWConfig_ResolveMatchesWhatNewPoWServiceActuallyUses(t *testing.T) {
	for _, pc := range []config.PoWConfig{
		{}, // 全未配
		{FailuresEnable: 1, BaseDifficulty: 6, RampDifficulty: 10, StepPerFailure: 3, AdaptiveCeiling: 17, TTLSec: 60},
		{BaseDifficulty: 9}, // 只配一项,其余走默认
	} {
		svc, err := NewPoWService(nil, nil,
			pc.FailuresEnable, pc.BaseDifficulty, pc.RampDifficulty,
			pc.StepPerFailure, pc.AdaptiveCeiling, pc.TTLSec)
		if err != nil {
			t.Fatalf("%+v 构造失败: %v", pc, err)
		}
		if got, want := svc.failuresEnable, pc.ResolveFailuresEnable(); got != want {
			t.Errorf("%+v: failuresEnable 服务侧 %d ≠ Resolve %d", pc, got, want)
		}
		if got, want := svc.baseDifficulty, pc.ResolveBaseDifficulty(); got != want {
			t.Errorf("%+v: baseDifficulty 服务侧 %d ≠ Resolve %d", pc, got, want)
		}
		if got, want := svc.rampDifficulty, pc.ResolveRampDifficulty(); got != want {
			t.Errorf("%+v: rampDifficulty 服务侧 %d ≠ Resolve %d", pc, got, want)
		}
		if got, want := svc.stepPerFailure, pc.ResolveStepPerFailure(); got != want {
			t.Errorf("%+v: stepPerFailure 服务侧 %d ≠ Resolve %d", pc, got, want)
		}
		if got, want := svc.adaptiveCeiling, pc.ResolveAdaptiveCeiling(); got != want {
			t.Errorf("%+v: adaptiveCeiling 服务侧 %d ≠ Resolve %d", pc, got, want)
		}
		if got, want := svc.ttlSec, pc.ResolveTTLSec(); got != want {
			t.Errorf("%+v: ttlSec 服务侧 %d ≠ Resolve %d", pc, got, want)
		}
	}
}

// TestIssueChallenge_CountsRampedIssuesSeparately ramped 计数只统计「高于 base」的出题。
//
// 这个计数器是自适应闸门在生产里的**唯一**信号(此前既无日志也无指标),所以它自己的口径
// 必须钉死:多计会让运维以为一直有人在爆破,少计会让真爆破期间它一动不动 —— 两种错法都
// 直接毁掉这个信号的意义。
func TestIssueChallenge_CountsRampedIssuesSeparately(t *testing.T) {
	svc, err := NewPoWService(nil, nil, 0, 0, 0, 0, 0, 0) // base=8 ramp=14 ceiling=22
	if err != nil {
		t.Fatal(err)
	}

	// base 档出题若干次:ramped 必须一直是 0。
	for i := 0; i < 3; i++ {
		if _, err := svc.IssueChallenge(svc.ComputeDifficulty(0)); err != nil {
			t.Fatalf("base 档出题失败: %v", err)
		}
	}
	if got := svc.MetricsSnapshot().IssuedRamped; got != 0 {
		t.Errorf("只出过 base 档的题,ramped = %d,应为 0", got)
	}

	// 跨过阈值:每次都要计入。
	if _, err := svc.IssueChallenge(svc.ComputeDifficulty(config.PoWDefaultFailuresEnable)); err != nil {
		t.Fatalf("ramp 档出题失败: %v", err)
	}
	if _, err := svc.IssueChallenge(svc.ComputeDifficulty(99)); err != nil { // 封顶档
		t.Fatalf("封顶档出题失败: %v", err)
	}
	snap := svc.MetricsSnapshot()
	if snap.IssuedRamped != 2 {
		t.Errorf("进了 ramp 的出题 2 次,ramped = %d", snap.IssuedRamped)
	}
	if snap.Issued != 5 {
		t.Errorf("总出题 5 次,issued = %d —— ramped 是 issued 的子集,不是另一套计数", snap.Issued)
	}
}

// TestNewPoWService_RejectsNegativeFailuresEnable 负值仍要 fail-fast。
//
// 0 从「阈值 0」变成「未配」之后,唯一还该被拒的就是负数;顺手确认错误信息里点出了
// 1 才是「第 1 次失败即 ramp」的写法,否则运维照旧会去写 0。
func TestNewPoWService_RejectsNegativeFailuresEnable(t *testing.T) {
	_, err := NewPoWService(nil, nil, -1, 0, 0, 0, 0, 0)
	if err == nil {
		t.Fatal("failures_enable=-1 必须拒绝启动")
	}
	if !strings.Contains(err.Error(), "1=ramp from the very first failure") {
		t.Errorf("错误信息该告诉运维怎么写才对,得到: %v", err)
	}
}
