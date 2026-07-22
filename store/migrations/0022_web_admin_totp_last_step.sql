-- 0022 (2026-07-22):web 后台 TOTP 增加「已用时间步」记录，做重放保护。
--
-- 背景:VerifyTOTP 此前是无状态的(只比对 secret+code+当前时间±1 步),不记录「这个码/这一步
-- 已经用过」。于是一枚被抓到的 6 位码在其 ~90s 有效窗口(±1 步)内可被重放登录(此前作为文档化
-- 取舍,依赖口令 + 账号锁定兜底)。本迁移加一列记录该 admin 最近一次**成功登录**所消费的 TOTP 时间步:
--
--   totp_last_used_step INTEGER NOT NULL DEFAULT 0
--
--     0  = 从未用过(存量老账号迁移后为 0，行为不变);
--     >0 = 最近一次成功 TOTP 登录消费的时间步 T=(unix/30)。
--
-- 登录校验成功后用条件 UPDATE 原子「消费」该步(WHERE totp_last_used_step < 新步)：
--   - 同一枚码重放 → 匹配到同一步 → 步不大于已消费步 → UPDATE 命中 0 行 → 拒绝(判为失败)。
--   - 正常下一次登录用更新的步 → 步更大 → 放行。
-- 代价:极少数「刚成功登录、~30s 内又用同一枚码再登一次」会被拒(需等下一个 30s 窗口)，可接受。

PRAGMA foreign_keys = ON;

ALTER TABLE web_admins ADD COLUMN totp_last_used_step INTEGER NOT NULL DEFAULT 0;
