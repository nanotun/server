-- 0023_devices_fixed_vip_empty_index.sql
--
-- 修:0008 给 devices.fixed_vip_v4/v6 建 partial UNIQUE 索引时只写了
-- `WHERE fixed_vip_* IS NOT NULL`,漏了 `AND fixed_vip_* != ''` —— 而 0002 给 users
-- 建同类索引时是带 `!= ''` 的。两者语义应一致。
--
-- 后果:若库里出现两台 device 的 fixed_vip_* 存的是**空串 ''** 而非 NULL(运维手工写库 /
-- 某些历史导入路径),它们会被唯一索引当成同一个「值」→ 触发 UNIQUE 冲突,后写的那台
-- 保存 fixed_vip 失败。正常写路径 SetDeviceFixedVIP 用 nullableString 已把 '' 归一成 NULL、
-- 不会触发;但索引本身应对存量 '' 行免疫,且与 users 版对齐。
--
-- 处理:先把已存在的 '' 归一成 NULL(与写路径语义一致,清掉存量脏值),再重建两个索引把 ''
-- 排除出唯一性判定。DROP + CREATE 均幂等(IF EXISTS / IF NOT EXISTS)。

UPDATE devices SET fixed_vip_v4 = NULL WHERE fixed_vip_v4 = '';
UPDATE devices SET fixed_vip_v6 = NULL WHERE fixed_vip_v6 = '';

DROP INDEX IF EXISTS idx_devices_fixed_v4;
DROP INDEX IF EXISTS idx_devices_fixed_v6;

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_fixed_v4
    ON devices(fixed_vip_v4) WHERE fixed_vip_v4 IS NOT NULL AND fixed_vip_v4 != '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_fixed_v6
    ON devices(fixed_vip_v6) WHERE fixed_vip_v6 IS NOT NULL AND fixed_vip_v6 != '';
