-- 0029_users_sso_empty_index.sql
--
-- 与 0002(users.fixed_vip)、0023(devices.fixed_vip)、0025(leases.vip)、0027(users.credential_id)
-- 对齐:users(sso_provider, sso_subject) 的复合唯一索引也应把空串 '' 排除出唯一性判定(第九轮深扫 LOW)。
--
-- 0001 建 idx_users_sso 时只写了 `WHERE sso_provider IS NOT NULL AND sso_subject IS NOT NULL`,漏了
-- `AND sso_provider != '' AND sso_subject != ''`。正常写路径经 nullableString 已把 '' 归一成 NULL,不会
-- 触发;但若库里出现两行 sso_provider='' / sso_subject=''(运维手工写库 / 历史导入 / SSO 回填异常),它们
-- 会被复合唯一索引当成同一「值对」→ 冲突。这是 0023/0027 点名的同一威胁模型,当时漏了 users 的 SSO 复合索引。
--
-- 处理:先把存量任一为 '' 的 SSO 字段归一成 NULL(与写路径一致 —— SSO 身份两字段要么都在、要么都不在,
-- 任一为空即视为「未绑定 SSO」全清 NULL),再重建索引排除 ''。DROP+CREATE 幂等。
UPDATE users SET sso_provider = NULL, sso_subject = NULL
    WHERE sso_provider = '' OR sso_subject = '';

DROP INDEX IF EXISTS idx_users_sso;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_sso ON users(sso_provider, sso_subject)
    WHERE sso_provider IS NOT NULL AND sso_subject IS NOT NULL
      AND sso_provider != '' AND sso_subject != '';
