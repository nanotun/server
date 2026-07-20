package store

// server_id.go(2026-05-26 第十一轮 + UUID 引入)— 服务器实例永久指纹。
//
// 目的
// ----
// 给每个 nanotun 安装实例分配一个**永久不变**的 UUID v4,写入 `app_settings.server_id`,
// 由所有导出的 server profile QR(`nanotun://v2`)携带为 `server_id` 字段。
//
// 与 credentials 同款语义
// -----------------------
// - credentials.id    = 用户级凭证指纹(users.credential_id,rotate-psk 不变)
// - profile.server_id = 服务器级实例指纹(本表 server_id,rotate / 换 host / 加节点 都不变)
//
// 客户端可按 server_id 做去重 / 覆盖语义:同 server_id 来了新 QR(host 换了 / reality
// 公钥换了 / 加了新入口)→ 覆盖既有条目,而不是当成另一台陌生服务器添加。
// (客户端这个逻辑后续 Rust / Swift 层会加,Go 端先把 wire 字段输出稳定。)
//
// 并发安全
// --------
// `GetOrInitServerID` 是 lazy init — 首次访问时若 setting 不存在,生成新 UUID 写库。
// 多个 admin 并发跑 `profile show` 时不能两人各拿到不同 UUID;实现走「first-writer-wins」:
//
//   1. UUID 候选 = google/uuid.NewString()
//   2. INSERT OR IGNORE 进 app_settings(已存在则 no-op,不覆盖既存值)
//   3. SELECT 当前 server_id 返回 —— 拿到第一个写入者的值
//
// 这是 SQLite-friendly 的 idempotent pattern:不依赖 BEGIN IMMEDIATE,也不会 race。

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// ServerIDKey 是 app_settings 表里持久化「服务器实例 UUID」的 key。
const ServerIDKey = "server_id"

// GetOrInitServerID 返回当前服务器的永久 UUID。
//
// 调用顺序:
//  1. 快路径:SELECT 一次;命中且非空 → 直接返回(99% 路径)。
//  2. 慢路径:尝试 INSERT OR IGNORE(`first-writer-wins`)+ rescue empty。
//     写失败(只读连接 / 磁盘满)→ 软降级返回 ("", nil) —— profile show 仍能
//     正常出 QR,只是当次缺 server_id 字段,客户端无法去重。
//  3. 二次 SELECT:取最终值。
//
// 实际上 server_id 的初始化由 [`Migrate`] 兜底(详见 `migrations.go` 末尾的
// `ensureServerID` hook);本函数保留软降级以应对极端 case:管理员在只读连接
// 上、且 schema 未跑过迁移就调 profile show(理论上不该发生,因为 server /
// nanotun-web 任一进程启动时都已跑过 migration)。
//
// 返回值保证:
//   - 非空字符串 = 36 位标准 UUID(google/uuid 默认 v4 格式)
//   - 调用同一 store 实例任意次,返回值**绝对一致**(以第一次写入为准)
//   - 写失败时返回 ("", nil),**不**返回 error —— 调用方按「软降级」处理
func (s *Store) GetOrInitServerID(ctx context.Context) (string, error) {
	if s == nil || s.db == nil {
		return "", errors.New("store: GetOrInitServerID on nil store")
	}

	// 快路径
	if v, ok, err := s.SettingsGet(ctx, ServerIDKey); err == nil && ok {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed, nil
		}
	}

	// 慢路径:生成候选 UUID + 原子幂等写入 + 取实际值。
	// wrote 标志仅 Migrate hook 在意(决定是否 log "initialized"),这里忽略。
	if _, err := s.ensureServerID(ctx); err != nil {
		// 软降级:写失败常见于只读连接(profile show 走 readOnly=true)。
		// migration 已跑过时不会到这里 — 走快路径就 OK 了。
		// 极端 case 下返回空 + nil,让 profile 仍能正常出,只是这次 QR 没 server_id。
		return "", nil
	}

	// 二次 SELECT:取实际生效值。前面 ensureServerID 保证此时一定有 valid UUID。
	v, ok, err := s.SettingsGet(ctx, ServerIDKey)
	if err != nil {
		return "", fmt.Errorf("store: re-read server_id: %w", err)
	}
	if !ok {
		// 极不可能:刚 INSERT OR IGNORE 完竟然 SELECT 不到,只能是 DB 异常。
		return "", errors.New("store: server_id missing after ensure (db corruption?)")
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", errors.New("store: server_id empty after ensure")
	}
	return v, nil
}

// ensureServerID 在 server_id 不存在时生成一个并 INSERT OR IGNORE,在已存在
// 时 no-op。可被多次调用,幂等。**需要写连接**(只读连接会返回 readonly error)。
//
// 设计上由 [`Store.Migrate`] 在 schema 升级末尾调一次,把「装机自动生成 UUID」
// 与 schema_version 写入挂在同一事务时序里 — 任何走过 Migrate 的进程,后续
// 用只读连接读 server_id 都保证拿得到。
//
// 与 GetOrInitServerID 的区别:本函数不返回值(只确保已落库),专注于"幂等
// 写入"语义;读路径走 SettingsGet / GetServerID。
//
// 返回 wrote = true 表示本次调用是 first-writer:实际 INSERT 了一条新行,或者
// rescue 了一条 value=” 的旧行。caller(典型是 Migrate hook)据此决定是否 log
// 一条 "server_id initialized" 让运维知道这台机器是这一刻首次拿到 UUID。
// false 表示 no-op(已有合法 UUID)— 重复启动 / 并发 caller 第二人 / 等等。
func (s *Store) ensureServerID(ctx context.Context) (wrote bool, err error) {
	if s == nil || s.db == nil {
		return false, errors.New("store: ensureServerID on nil store")
	}
	candidate := uuid.NewString()

	// INSERT OR IGNORE:行不存在 → 落库;存在(含空串)→ no-op。
	// 保证「全新部署」first-writer-wins:并发调用只有第一个 INSERT 成功,
	// 后续都 IGNORE,最终所有 caller 读到同一值。
	res, ierr := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO app_settings(key, value) VALUES(?, ?)`,
		ServerIDKey, candidate,
	)
	if ierr != nil {
		return false, fmt.Errorf("store: insert server_id: %w", ierr)
	}
	insertedRows, _ := res.RowsAffected()
	// rescue empty:历史数据若 value='' 时 INSERT OR IGNORE 跳过,这里用
	// CAS-style UPDATE 只覆盖空值,不动合法 UUID。
	rres, uerr := s.db.ExecContext(ctx,
		`UPDATE app_settings SET value = ? WHERE key = ? AND value = ''`,
		candidate, ServerIDKey,
	)
	if uerr != nil {
		return false, fmt.Errorf("store: rescue empty server_id: %w", uerr)
	}
	rescuedRows, _ := rres.RowsAffected()
	wrote = insertedRows > 0 || rescuedRows > 0
	if wrote {
		// 单进程「首次为这台机器写下 server_id」的可观察性入口:运维通过 journalctl
		// 看到这条 log 就知道「装机时机」+「UUID 值」,不必每次查 sqlite。已有 UUID
		// 时(insertedRows=0 && rescuedRows=0)沉默,以免 systemd restart 噪音。
		event := "[migrate] server_id initialized"
		if rescuedRows > 0 && insertedRows == 0 {
			event = "[migrate] server_id rescued from empty value"
		}
		logrus.WithField("server_id", candidate).Info(event)
	}
	return wrote, nil
}

// GetServerID 是 GetOrInitServerID 的只读版本:不生成,只读。
//
// 用于「我想知道当前 server_id,但不想触发首次生成」的诊断 / 监控场景。
// 比如 metrics 暴露当前 instance ID,init 时机应该走 GetOrInitServerID;
// runtime 暴露走 GetServerID 避免 metrics 抓取顺手触发持久化写入。
//
// 返回 ("", nil) 表示「key 不存在」,( "", err) 表示 DB 故障。
func (s *Store) GetServerID(ctx context.Context) (string, error) {
	if s == nil || s.db == nil {
		return "", errors.New("store: GetServerID on nil store")
	}
	v, ok, err := s.SettingsGet(ctx, ServerIDKey)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	return strings.TrimSpace(v), nil
}
