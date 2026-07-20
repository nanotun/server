-- nanotun schema v2
--
-- fixed_vip 跨用户唯一约束 + 同 lease 表中也唯一(虽然 lease 表已经有 partial UNIQUE)。
--
-- 背景:
--   * 0001 里 users.fixed_vip_v4/v6 只是普通 TEXT 列,没有 UNIQUE。admin CLI 的
--     `user set-fixed-vip --force` 可以强行让两个 user 钉同一个 vIP;
--   * 两人同时登录时,server 内存里 clientIPUsed 只能拦后到者,但 dbReservedVIPs
--     在 connectionsMu 外快照,极端竞态下两个新设备可能都拿到同一个 vIP;
--   * UpsertLease 即使 UNIQUE(vip) 撞了也只 Warn,客户端已经拿走 vIP,DB 没 lease 行
--     → 重启后 IP 漂移。
--
-- 这一版加 DB 级硬约束:partial UNIQUE INDEX(只对非 NULL 行生效,允许多人不设
-- fixed_vip)。一旦运维写库写出冲突就直接报 UNIQUE constraint failed,不会再形成
-- 「双人同地址」的伪状态。

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_fixed_vip_v4
    ON users(fixed_vip_v4)
    WHERE fixed_vip_v4 IS NOT NULL AND fixed_vip_v4 != '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_fixed_vip_v6
    ON users(fixed_vip_v6)
    WHERE fixed_vip_v6 IS NOT NULL AND fixed_vip_v6 != '';

-- 提示:
--   * lease.vip_v4/v6 与 users.fixed_vip_v4/v6 互相之间 *不能* 在 SQLite 里用 DB 级
--     约束跨表强制(SQLite 不支持表间 UNIQUE / 复合视图)。这部分应用层保证:
--     server.alloc_lease.go 在分配时把 store.AllUsedVIPs(union fixed + lease) 当占用集;
--     admin CLI 的 user set-fixed-vip / lease set 互查冲突。
--   * 升级注意:本 migration 在执行前,如果库里已经有跨用户重复的 fixed_vip,
--     migration 会失败(UNIQUE constraint failed)。运维需要先 admin user list 找出冲突
--     行,改一行后再 systemctl start。
