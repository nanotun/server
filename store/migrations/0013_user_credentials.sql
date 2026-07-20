-- 0013 (2026-05-25):users 表加 credential_id + credential_created_at,支撑
-- 「profile / credentials 解耦」(`nanotun-cred://v1?d=...`)。
--
-- 设计:
--   credential_id          TEXT  UUID v4(36 字符含 "-"),user create 时分配,**之后稳定不变**。
--                                rotate-psk 路径只换 psk_hash + credential_created_at,
--                                credential_id 保留 → client 按 UUID 索引,新 QR 自然覆盖旧 PSK。
--   credential_created_at  INT   unix epoch seconds(UTC),每次 psk_hash 变化时刷新。
--
--   两列都 NULL 容忍:0001_init 起的老 user 没有这俩字段,首次 `credentials show`
--   命中后由上层 lazy backfill(生成新 UUID + now 写回)。Migration 不在 SQL 里
--   生成 UUID(SQLite 没原生 UUID,且 backfill 时间戳应反映「PSK 实际被设的那一刻」,
--   M0 老 user 的 created_at 已接近 PSK 设置时间,但避免误导,统一走 lazy 路径)。
--
-- 与 users.psk_hash 关系:这俩字段**只供 admin/client 流转用**,登录路径(auth/psk.go)
-- 完全不读,所以 server 端用户模型 + argon2id 校验逻辑零改动。

PRAGMA foreign_keys = ON;

ALTER TABLE users ADD COLUMN credential_id TEXT;
ALTER TABLE users ADD COLUMN credential_created_at INTEGER;

-- UNIQUE 索引:credential_id 理论上 UUID v4 全局唯一(2^122 熵 > 5e36),
-- 但 NULL 允许多行(老 user 都 NULL),所以加 partial unique index 守护非空冲突。
-- 上层任何写入都用 google/uuid,这条索引仅作纵深防御。
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_credential_id
    ON users(credential_id)
    WHERE credential_id IS NOT NULL;
