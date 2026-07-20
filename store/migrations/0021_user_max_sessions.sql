-- 0021 (2026-07-20):users 表加 max_sessions —— 「按账号限制并发会话数」。
--
-- 设计(与全局 [server].max_sessions_per_user 两级叠加):
--   max_sessions  INTEGER NOT NULL DEFAULT 0
--
--     0  = 跟随全局配置(默认;存量老 user 迁移后全是 0 → 行为不变);
--     >0 = 该账号并发会话上限(覆盖全局值,可比全局更松或更紧);
--     -1 = 该账号显式不限(即便全局设了上限也放行)。
--
-- 生效值在**登录时定格**到 Connection(cmd/nanotund/auth_login.go),与全局值热更同口径:
-- 改动仅对未来登录生效,现役会话不回踢。
--
-- 同步变更:全局 [server].max_sessions_per_user 的缺省语义从「0 = 5」改为
-- 「0 = 不限制」(2026-07-20 需求:默认不限制;要限流的部署显式配数字)。

PRAGMA foreign_keys = ON;

ALTER TABLE users ADD COLUMN max_sessions INTEGER NOT NULL DEFAULT 0;
