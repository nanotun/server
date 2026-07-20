-- 0008_devices_fixed_vip.sql
--
-- 把「固定 vIP」从 users 表搬到 devices 表。
--
-- 历史 schema 把 fixed_vip_v4 / fixed_vip_v6 钉在 users 表上，意味着一个用户
-- 全网只能拥有一个固定 vIP。但本项目的协议层 LoginReq.device_uuid 强制 RFC 4122 v4,
-- (user_id, device_uuid) 在 devices 表本来就 UNIQUE,leases 也是 per-device。
-- 所以「固定 vIP」的天然粒度应该是 device — 一个用户的 N 台设备每台都可以独立
-- 钉死一个 vIP（典型场景:用户的服务器 / 路由器 / Mac 桌面 三台都想要稳定 IP）。
--
-- 本迁移做四件事：
--   1) 给 devices 加 fixed_vip_v4 / fixed_vip_v6 两列,并为 NOT NULL 值建 UNIQUE 索引
--      (与 leases 表里 vIP UNIQUE 一致,保证两个设备不会预订同一个 vIP)。
--   2) 把现有 users.fixed_vip_* 的值搬到该用户「最早创建的那台 device」上 —— 这是最
--      不破坏现有运维语义的选择(最老的设备通常是用户的主力机)。同 user 的其它
--      device 维持自动分配。如果用户根本没设备,该 fixed_vip 直接丢弃(因为它本来
--      就没生效过 — 没设备就不会进登录路径)。
--   3) DROP users.fixed_vip_v4 / fixed_vip_v6 两列。SQLite 3.35+ 支持 DROP COLUMN,
--      项目用 modernc.org/sqlite v1.50.1（内嵌 3.46+),稳。
--      drop 后 server / admin / web 代码也都不会再误读这两列,语义彻底清晰。
--   4) DROP idx_devices_user 之类不存在的索引就不动;新建的 UNIQUE 索引带
--      WHERE NULL 过滤,跟 leases 的索引风格一致(SQLite 多个 NULL 不视为冲突)。

ALTER TABLE devices ADD COLUMN fixed_vip_v4 TEXT;
ALTER TABLE devices ADD COLUMN fixed_vip_v6 TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_fixed_v4
    ON devices(fixed_vip_v4) WHERE fixed_vip_v4 IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_fixed_v6
    ON devices(fixed_vip_v6) WHERE fixed_vip_v6 IS NOT NULL;

-- 把 users.fixed_vip_* 搬到「该 user 最早创建的 device」。
-- 用相关子查询 + ROWID 标识「最早 device」(id 升序天然 = 创建顺序)。
-- 注意 SQLite 不支持 UPDATE ... FROM 在所有版本上,所以这里用相关子查询。
UPDATE devices
SET fixed_vip_v4 = (
    SELECT u.fixed_vip_v4
    FROM users u
    WHERE u.id = devices.user_id
      AND u.fixed_vip_v4 IS NOT NULL
)
WHERE id IN (
    SELECT MIN(id) FROM devices GROUP BY user_id
);

UPDATE devices
SET fixed_vip_v6 = (
    SELECT u.fixed_vip_v6
    FROM users u
    WHERE u.id = devices.user_id
      AND u.fixed_vip_v6 IS NOT NULL
)
WHERE id IN (
    SELECT MIN(id) FROM devices GROUP BY user_id
);

-- 彻底废弃 users.fixed_vip_* —— 直接 DROP COLUMN。
-- 若部署中数据已搬到 devices,旧列可以安全删除;若用户从未配过 fixed_vip,
-- 列里都是 NULL,删除无影响。
--
-- 注意:0002 给这两列建过 partial UNIQUE INDEX(idx_users_fixed_vip_v4/v6),
-- SQLite 的 ALTER TABLE DROP COLUMN 要求该列上不能挂任何索引,
-- 否则报 "error in index idx_users_fixed_vip_v4 after drop column: no such column"。
-- 所以必须先 DROP INDEX,再 DROP COLUMN。
DROP INDEX IF EXISTS idx_users_fixed_vip_v4;
DROP INDEX IF EXISTS idx_users_fixed_vip_v6;

ALTER TABLE users DROP COLUMN fixed_vip_v4;
ALTER TABLE users DROP COLUMN fixed_vip_v6;
