package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
)

// vipCanonicalizedKey 是 canonicalizeStoredVIPs 的一次性完成标记(app_settings)。
const vipCanonicalizedKey = "vip_canonicalized"

// canonicalizeStoredVIPs 是一次性 Go 迁移兜底:把 leases.vip_v4/v6 与 devices.fixed_vip_v4/v6
// 里**非规范**的历史值(第七轮 canonicalVIP 写路径修复**之前**落库的、如大写 / 未压缩 IPv6,
// 例如 "FD00::2"、"2001:db8:0:0:0:0:0:2")重写为 netip.Addr 规范文本,使写路径的新约束与存量
// 数据处于同一文本域。
//
// 第九轮深扫 MED:canonicalVIP 只在**新写入**(UpsertLease / SetDeviceFixedVIP)归一,漏了存量。
// 升级前落过非规范 IPv6 fixed-VIP 的部署里,那些行仍会绕过 devices/leases 的部分 UNIQUE 索引、
// UpsertLease↔SetDeviceFixedVIP 的跨表 BINARY 守卫、AllUsedVIPs 去重与 GcOrphanLeases 守卫(全是
// 精确字符串比较)—— 分配器按规范式 "fd00::2" 生成候选,认不出存量的 "FD00::2",可能把同一地址
// 再分配给别的设备,造成双占 / 路由黑洞。本 hook 补上「存量归一」这一半,根治该窗口。
//
// 为什么走 Go hook 而非纯 SQL migration:SQLite 无法在纯 SQL 里做 IPv6 的大小写折叠 / 零段压缩。
// 沿用 Migrate 末尾 ensureServerID 同款「Go 端一次性 hook」模式,由跑过 Migrate 的进程触发。
//
// 幂等 + 碰撞安全:
//   - 用 settings 键 vipCanonicalizedKey 守成一次性;已跑过直接返回。
//   - 即便键未落(中途崩溃)下次重跑仍幂等 —— 已规范的值 canonical==current 直接跳过。
//   - 若某行规范化后会与**同表同列另一行**撞车(说明存量本已双占,或两行归一到同一地址),跳过
//     并 log warn,**绝不**因 UNIQUE 冲突让整条迁移 / 服务启动失败;裁决赢家留给运维。
//
// 调用方(Migrate)已持有 s.mu;本函数只用 s.db / tx 直连,不再调任何会重取 s.mu 的 Store 方法。
func (s *Store) canonicalizeStoredVIPs(ctx context.Context) error {
	// 已跑过 → 跳过(幂等守卫)。SettingsGet 不取 s.mu,可在 Migrate 持锁期内安全调用。
	if v, ok, err := s.SettingsGet(ctx, vipCanonicalizedKey); err != nil {
		return fmt.Errorf("store: canonicalize vips: read done flag: %w", err)
	} else if ok && v == "1" {
		return nil
	}

	// 第十五轮深扫 LOW:碰撞检查从「同表同列」扩到**跨表配对列**(leases.vip ↔ devices.fixed_vip 同族)。
	// 此前只查同表:把 leases.vip_v6 从 "FD00::2" 归一成 "fd00::2" 时,只看 leases 里有没有 "fd00::2",看不到
	// **别的设备**的 devices.fixed_vip_v6 已是 "fd00::2" → 归一后跨表双占,却被落库。ownerCol/pOwnCol 用于**排除
	// 同一设备**的合法配对(SetDeviceFixedVIP 会同写 device.fixed_vip + 同值 manual lease,同设备两处相等是正常的)。
	type vipCol struct {
		table    string
		col      string
		ownerCol string // 本表内标识「归属设备」的列:leases→device_id,devices→id
		pTable   string // 配对的另一表
		pCol     string // 配对列(同族 v4/v6)
		pOwnCol  string // 配对表内标识归属设备的列
	}
	cols := []vipCol{
		{"leases", "vip_v4", "device_id", "devices", "fixed_vip_v4", "id"},
		{"leases", "vip_v6", "device_id", "devices", "fixed_vip_v6", "id"},
		{"devices", "fixed_vip_v4", "id", "leases", "vip_v4", "device_id"},
		{"devices", "fixed_vip_v6", "id", "leases", "vip_v6", "device_id"},
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: canonicalize vips: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// 第十一轮深扫 MED:**先写后读**,把本 tx 变成 write-first —— 与本包所有热路径(UpsertLease /
	// mutateWebAdminEnsuringAdmin 等)刻意保持的纪律一致。SQLite WAL 下 DEFERRED tx 在**首条语句**
	// 取快照:若首条是 SELECT(read snapshot),而另一连接(如滚动升级期仍在服务的旧实例:写 audit /
	// touch lease / session GC,或第二个进程)在本 tx 首次写之前 commit,则本 tx 的写会以
	// SQLITE_BUSY_SNAPSHOT 失败,而 busy_timeout **不重试**该错 —— 导致 Migrate/启动非可重试地失败。
	// Migrate 的 flock + s.mu 只串行化「其它 Migrate」,拦不住旧实例的常规写。故这里把标记的写
	// **前置为 tx 首条语句**:立即拿到 reserved 写锁 / 写级快照,后续 SELECT/UPDATE 不再被并发 commit 打断。
	//
	// 第十四轮深扫 MED:首条**只写 '0'(进行中)**,不再直接写 '1'。真正的完成标记 '1' 留到循环结束、且
	// **skipped==0**(无碰撞跳过)时再 UPDATE(见下方 finalize)。此前无条件写 '1':一旦某行因规范形已被占用
	// 被跳过,也照样落 '1' → 下次 Migrate 永久 no-op,残留非规范 VIP 再不被处理 → AllUsedVIPs 去重失配 / 双占。
	// 现在有跳过就把标记留在 '0',下次启动重跑本 hook(已规范行 no-op,冲突行继续告警),直到运维释放冲突方后
	// 自动收尾。'0' 与 '1' 都在同一 tx,commit 一起生效、rollback(中途崩溃)一起回滚,幂等不变。
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO app_settings(key,value) VALUES(?, '0')
		 ON CONFLICT(key) DO UPDATE SET value='0'`,
		vipCanonicalizedKey,
	); err != nil {
		return fmt.Errorf("store: canonicalize vips: reserve done flag: %w", err)
	}

	rewritten, skipped := 0, 0
	for _, c := range cols {
		// 表名 / 列名均为**硬编码常量**(非入参),无注入面。只扫非空值。同时取「归属设备」列(owner),
		// 供下方跨表碰撞检查排除同一设备的合法 fixed_vip↔sticky-lease 配对。
		//nolint:gosec // identifiers are compile-time constants, not user input
		q := fmt.Sprintf("SELECT id, %s, %s FROM %s WHERE %s IS NOT NULL AND %s != ''",
			c.ownerCol, c.col, c.table, c.col, c.col)
		rows, err := tx.QueryContext(ctx, q)
		if err != nil {
			return fmt.Errorf("store: canonicalize vips: scan %s.%s: %w", c.table, c.col, err)
		}
		// 先把本列所有 (id,owner,val) 读进内存再逐行 UPDATE —— 不在遍历游标的同时对同表发写,
		// 避免 SQLite 游标失效 / 未定义行为。
		type row struct {
			id    int64
			owner int64
			val   string
		}
		var pending []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.owner, &r.val); err != nil {
				rows.Close()
				return fmt.Errorf("store: canonicalize vips: scan row %s.%s: %w", c.table, c.col, err)
			}
			pending = append(pending, r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("store: canonicalize vips: rows %s.%s: %w", c.table, c.col, err)
		}
		rows.Close()

		for _, r := range pending {
			canonical := canonicalVIP(r.val)
			if canonical == r.val {
				continue // 已规范,no-op。
			}
			// 碰撞检查(两处):
			//   1) 同表同列已有 canonical(既有规范行,或本轮已改写的另一行);
			//   2) 跨表配对列(另一表同族列)被**别的设备**占用 —— 同设备的 fixed_vip↔sticky-lease 配对合法,排除。
			// 任一命中即视为「规范形已被占用」→ 存量本已双占 → 跳过,不由迁移裁决赢家(标记留 '0' 下次重跑)。
			//nolint:gosec // identifiers are compile-time constants, not user input
			sameQ := fmt.Sprintf("SELECT 1 FROM %s WHERE %s=? LIMIT 1", c.table, c.col)
			//nolint:gosec // identifiers are compile-time constants, not user input
			crossQ := fmt.Sprintf("SELECT 1 FROM %s WHERE %s=? AND %s != ? LIMIT 1", c.pTable, c.pCol, c.pOwnCol)
			collided := false
			var dummy int
			switch scanErr := tx.QueryRowContext(ctx, sameQ, canonical).Scan(&dummy); {
			case scanErr == nil:
				collided = true
			case errors.Is(scanErr, sql.ErrNoRows):
				switch cErr := tx.QueryRowContext(ctx, crossQ, canonical, r.owner).Scan(&dummy); {
				case cErr == nil:
					collided = true
				case errors.Is(cErr, sql.ErrNoRows):
					// 两处均无碰撞,可安全重写。
				default:
					return fmt.Errorf("store: canonicalize vips: cross-table collision check %s.%s vs %s.%s: %w",
						c.table, c.col, c.pTable, c.pCol, cErr)
				}
			default:
				return fmt.Errorf("store: canonicalize vips: collision check %s.%s: %w", c.table, c.col, scanErr)
			}
			if collided {
				skipped++
				logrus.WithFields(logrus.Fields{
					"table":     c.table,
					"col":       c.col,
					"id":        r.id,
					"raw":       r.val,
					"canonical": canonical,
				}).Warn("[store] VIP 规范化跳过:规范形已被占用(存量双占/跨表),请人工核对释放冲突方")
				continue
			}
			//nolint:gosec // identifiers are compile-time constants, not user input
			upd := fmt.Sprintf("UPDATE %s SET %s=? WHERE id=?", c.table, c.col)
			if _, err := tx.ExecContext(ctx, upd, canonical, r.id); err != nil {
				return fmt.Errorf("store: canonicalize vips: update %s.%s id=%d: %w", c.table, c.col, r.id, err)
			}
			rewritten++
		}
	}

	// 第十四轮深扫 MED:只有**全部**规范化成功(skipped==0)才把标记落到最终态 '1';否则留 '0',下次启动重跑。
	// finalize 是本 tx 的又一次写(前面已有 '0' 写 + 可能的 UPDATE),不影响 write-first 语义。
	if skipped == 0 {
		if _, err := tx.ExecContext(ctx,
			`UPDATE app_settings SET value='1' WHERE key=?`, vipCanonicalizedKey); err != nil {
			return fmt.Errorf("store: canonicalize vips: finalize done flag: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: canonicalize vips: commit: %w", err)
	}
	if rewritten > 0 || skipped > 0 {
		logrus.WithFields(logrus.Fields{
			"rewritten": rewritten,
			"skipped":   skipped,
		}).Info("[store] 存量 VIP 规范化完成(一次性)")
	}
	return nil
}
