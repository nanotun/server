-- 0011 (2026-05-23):per-device 带宽限速 + 全局默认。
--
-- 历史(P0-4):只在 users 表有 bandwidth_up_bps / bandwidth_down_bps,粒度太粗 ——
-- 一个 user 名下多台设备会拿到同一份限速;管理员想「家里的电视盒子限到 5MiB/s,
-- 手机不限」做不到。
--
-- 设计:
--   1) devices 加 rate_upload_bps / rate_download_bps:per-device 限速,字节/秒。
--      0 = 沿用全局默认(本表 + app_settings + toml 三级回退)。
--   2) app_settings 加 rate_default_upload_bps / rate_default_download_bps:
--      全局默认 cap,web/CLI 可热改;0 = 沿用 toml [server].upload_rate/download_rate。
--      与 toml 关系:settings >0 时**覆盖** toml(不再 min,设计更直观);
--      与 users.bandwidth_*_bps 关系:user 字段仍作为「该 user 上限」与 device 维度
--      取 min(语义已在 cmd/nanotund/rate_limit_test.go 写明),所以本次迁移**不**动 users 表。
--
-- 最终在 server 端选取的有效限速:
--   eff_up   = min_positive(device.rate_upload_bps,
--                           settings.rate_default_upload_bps OR toml.upload_rate,
--                           user.bandwidth_up_bps)
--   eff_down = 同上替换 download
--
-- min_positive 把 0 当 +∞,保证「某层不限」不会让更严的层被放宽。

PRAGMA foreign_keys = ON;

ALTER TABLE devices ADD COLUMN rate_upload_bps   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN rate_download_bps INTEGER NOT NULL DEFAULT 0;

INSERT OR IGNORE INTO app_settings(key, value) VALUES
    ('rate_default_upload_bps',   '0'),
    ('rate_default_download_bps', '0');
