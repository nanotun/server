-- 0027_users_credential_id_empty_index.sql
--
-- 与 0023(devices.fixed_vip)、0025(leases.vip)、0002(users.fixed_vip)对齐:users.credential_id 的唯一
-- 索引也应把空串 '' 排除出唯一性判定(第四轮深扫 MED)。
--
-- 0013 建 idx_users_credential_id 时只写了 `WHERE credential_id IS NOT NULL`,漏了 `AND credential_id != ''`。
-- 正常写路径经 nullableString 已把 '' 归一成 NULL,不会触发;但若库里出现两行 credential_id=''(运维手工写库 /
-- 历史导入 / 迁移回填异常),它们会被唯一索引当成同一「值」→ 后写方 UPSERT / BackfillUserCredentialID 误报
-- ErrDuplicate,卡住用户创建 / 凭据回填。这是 0023 点名的同一威胁模型,当时漏了 users.credential_id。
--
-- 处理:先把存量 '' 归一成 NULL(与写路径一致),再重建索引排除 ''。DROP+CREATE 幂等。
UPDATE users SET credential_id = NULL WHERE credential_id = '';

DROP INDEX IF EXISTS idx_users_credential_id;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_credential_id
    ON users(credential_id) WHERE credential_id IS NOT NULL AND credential_id != '';
