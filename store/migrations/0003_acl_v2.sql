-- nanotun schema v3 — ACL v2:proto / port range / 出口标志 / default action
--
-- 背景:
--   * v1 的 acl_pairs(src_user, dst_user, action) 只能在「用户 → 用户」粒度做粗放裁决,
--     无法区分「禁止访问对方的 SSH 22 端口、但允许 HTTP 80」这种常见场景;
--   * 出口流量(dst 不是 vIP)完全不在 ACL 视野里 —— 一个被 disable_exit 的 user 仍可经
--     nanotun 出公网,数据面没有任何阻拦;
--   * 默认动作硬编码为「无规则 → 全放行」,无法做「白名单」模型(默认 deny)。
--
-- v3 在不破坏旧规则(都默认 proto='' / dst_port_lo/hi=0 / dst_kind='user')的前提下扩展:
--
--   1. acl_pairs 新增列:
--        proto        TEXT   — '' = any、'tcp'、'udp'、'icmp'、'icmpv6'
--        dst_port_lo  INTEGER— 0 = any;>0 时表示 dst 端口范围下界(闭)
--        dst_port_hi  INTEGER— 0 = lo;>0 时表示 dst 端口范围上界(闭)
--        dst_kind     TEXT   — 'user'(默认,对方 vIP 流量)或 'exit'(出口公网)
--                              dst_kind='exit' 时 dst_user_id 必须为 NULL(规则适用任意外网目标);
--                              src_user_id=NULL 表示「任意用户出公网」。
--
--   2. UNIQUE 约束扩到包含 proto + port + dst_kind,允许多条互不冲突的精细规则。
--
--   3. app_settings 新键 acl_default_action,值 'allow'(默认,向后兼容)或 'deny'。
--      数据面命中规则集为空 / 所有规则都没命中时按此值兜底。
--
-- 升级安全:全部列都带 DEFAULT,老行可以直接读出新列的默认值,运行期 acl_runtime
-- 重建 snapshot 后行为与 v2 完全一致;管理员后续按需新增带新字段的规则即可。

-- SQLite 不允许直接 DROP 由 UNIQUE 约束自建的 sqlite_autoindex,
-- 因此采用「重建表 + copy 数据」的标准 12-step 模式。
-- (https://sqlite.org/lang_altertable.html#otheralter)
--
-- 0003 重建 acl_pairs:
--   1. 重命名旧表为 _v2_old;
--   2. 用新 schema(含 proto/dst_port_lo/dst_port_hi/dst_kind 列 + 新 UNIQUE 组合)创建 acl_pairs;
--   3. 把旧行 SELECT/INSERT 进去,新列取默认值;
--   4. 删掉旧表 + 重建旧索引(此处 v1 没有非约束自动索引)。
--
-- 【勘误 · 深扫第八轮 LOW】下面这两条 `PRAGMA foreign_keys = OFF/ON` 在事务内是
-- **no-op** —— SQLite 明确规定该 pragma 不能在一个打开的事务里更改(Migrate 用 BeginTx
-- 包裹每个 migration),所以它既不会真的关掉、也不会真的开启 FK 检查,仅作历史注释保留。
-- 本 migration 之所以仍然安全,与 FK 开关无关:重建表时新行全部来自旧表(约束一致,
-- 不会有悬空引用),且 CASCADE 只挂在 acl_pairs→users 上,DROP 旧表不触发级联。
-- 【给未来的重建型 migration】若确实需要在事务内推迟 FK 检查,请用
-- `PRAGMA defer_foreign_keys = ON;`(它对事务内生效,COMMIT 时统一校验),而不是本行。

PRAGMA foreign_keys = OFF;

ALTER TABLE acl_pairs RENAME TO _acl_pairs_v2_old;

CREATE TABLE acl_pairs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    src_user_id   INTEGER REFERENCES users(id) ON DELETE CASCADE,
    dst_user_id   INTEGER REFERENCES users(id) ON DELETE CASCADE,
    action        TEXT NOT NULL DEFAULT 'allow',
    proto         TEXT NOT NULL DEFAULT '',
    dst_port_lo   INTEGER NOT NULL DEFAULT 0,
    dst_port_hi   INTEGER NOT NULL DEFAULT 0,
    dst_kind      TEXT NOT NULL DEFAULT 'user',
    created_at    INTEGER NOT NULL,
    -- NULL 在 SQLite UNIQUE 里被视作彼此不等,所以通配(src/dst=NULL)规则不会被这条约束拦,
    -- 应用层(admin CLI acl add)负责防止「重复加同名通配」。
    UNIQUE(src_user_id, dst_user_id, action, proto, dst_port_lo, dst_port_hi, dst_kind)
);

INSERT INTO acl_pairs(id, src_user_id, dst_user_id, action, proto, dst_port_lo, dst_port_hi, dst_kind, created_at)
SELECT id, src_user_id, dst_user_id, action, '', 0, 0, 'user', created_at
  FROM _acl_pairs_v2_old;

DROP TABLE _acl_pairs_v2_old;

PRAGMA foreign_keys = ON;

INSERT OR IGNORE INTO app_settings(key, value) VALUES
    ('acl_default_action', 'allow');
