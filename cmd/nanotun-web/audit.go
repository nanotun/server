package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/store"
)

// M2:audit 写库辅助。
//
// 所有 nanotun-web 触发的写操作(创建/修改/删除用户、ACL、设备、kick、reload …)
// 都必须经此走一遍,actor 统一为 "web:<username>",方便后续从 audit_logs 区分
// nanotund 自身的 system actor 与 nanotun-admin CLI 的 "cli:<host>"。
//
// 不让 audit 写库失败掩盖业务操作:audit 失败只 Warn,主路径已经写完不回滚。

type Auditor struct {
	store *store.Store
}

func NewAuditor(s *store.Store) *Auditor {
	return &Auditor{store: s}
}

// Write 写一条 audit。caller 是已登录的 admin(可为 nil → "web:anonymous")。
//
// detail 建议尽量简短的人类可读说明,JSON 也行,但不要包含 PSK / password 明文。
func (a *Auditor) Write(ctx context.Context, admin *store.WebAdmin, action, target, detail string) {
	if a == nil || a.store == nil {
		return
	}
	actor := "web:anonymous"
	if admin != nil {
		actor = "web:" + admin.Username
	}
	if err := a.store.Audit(ctx, actor, action, target, detail); err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"actor":  actor,
			"action": action,
			"target": target,
		}).Warn("[web] audit 写入失败,业务路径已成功")
	}
}

// WriteFromRequest 从 r.Context() 自动取登录信息,handler 常用快捷形式。
func (a *Auditor) WriteFromRequest(r *http.Request, action, target, detail string) {
	a.Write(r.Context(), adminFromCtx(r.Context()), action, target, detail)
}

// FormatTarget 把若干 (key=val) 拼成 audit 的 target 字段。
// 例:FormatTarget("user", 12) → "user/12"。
func FormatTarget(kind string, id any) string {
	return fmt.Sprintf("%s/%v", kind, id)
}

// FormatDetail 把若干 k=v 拼成 audit 的 detail 字段。
// 例:FormatDetail("from", "10.0.0.1", "ua", "curl") → "from=10.0.0.1 ua=curl"。
//
// 对 PSK / password 字段提供白名单保护:keys 中含 "psk" / "password" / "secret"
// 时 value 全替成 "<redacted>",避免误把明文写进 audit_logs。
func FormatDetail(kv ...any) string {
	if len(kv)%2 != 0 {
		return "<bad detail>"
	}
	parts := make([]string, 0, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		k, _ := kv[i].(string)
		v := fmt.Sprintf("%v", kv[i+1])
		kLower := strings.ToLower(k)
		if strings.Contains(kLower, "psk") || strings.Contains(kLower, "password") ||
			strings.Contains(kLower, "secret") || strings.Contains(kLower, "token") {
			v = "<redacted>"
		}
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " ")
}
