-- 0025_leases_vip_empty_index.sql
--
-- 与 0023(devices)、0002(users)对齐:leases 的 vip 唯一索引也应把空串 '' 排除出唯一性判定
-- (第三轮深扫 L6)。
--
-- 0001 建 idx_leases_vip_v4/v6 时只写了 `WHERE vip_* IS NOT NULL`,漏了 `AND vip_* != ''`。
-- 正常写路径 UpsertLease 经 nullableString 已把 '' 归一成 NULL,不会触发;但若库里出现两行 vip_*=''
-- (运维手工写库 / 历史导入),它们会被唯一索引当成同一「值」→ 后写方 UpsertLease 误报 ErrDuplicate。
-- 这是 0023 自己点名的同一威胁模型,只是当时漏了 leases。
--
-- 处理:先把存量 '' 归一成 NULL(与写路径一致),再重建两个索引排除 ''。DROP+CREATE 幂等。

UPDATE leases SET vip_v4 = NULL WHERE vip_v4 = '';
UPDATE leases SET vip_v6 = NULL WHERE vip_v6 = '';

DROP INDEX IF EXISTS idx_leases_vip_v4;
DROP INDEX IF EXISTS idx_leases_vip_v6;

CREATE UNIQUE INDEX IF NOT EXISTS idx_leases_vip_v4
    ON leases(vip_v4) WHERE vip_v4 IS NOT NULL AND vip_v4 != '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_leases_vip_v6
    ON leases(vip_v6) WHERE vip_v6 IS NOT NULL AND vip_v6 != '';
