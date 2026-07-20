-- nanotun schema v4 — profile 吊销表(DEPRECATED 2026-05-25,DROPPED 2026-05-26)
--
-- 历史目的:profile QR 含 PSK,一旦泄露需要远程让它失效。reset PSK 是全局操作
-- 会影响该用户所有设备/profile;这里加 per-profile 粒度的「黑名单」:profile
-- 生成时塞一个随机 ID(pid),客户端在 LoginReq.ProfileID 上报,服务端查表命中
-- 即拒登 + audit。
--
-- 废弃原因(0013 credentials 解耦):profile QR 不再含 PSK,即使被截屏泄露也
-- 不能登录,pid 黑名单机制冗余。0014(2026-05-25)起 Go 代码已完全移除对本表的
-- 读写;0014_drop_revoked_profiles.sql(2026-05-26)正式 DROP TABLE。
--
-- 这条 0001~0013 之间的 CREATE TABLE 仍保留:老备份 / 老库做 schema diff 时
-- 看到 0004 → 0014 的完整轨迹,知道「此表在 v14 之前一直存在,然后被显式删除」。
-- 全新建库会顺序执行到 0014,建表 + 立刻删 — 多花几毫秒不重要。
--
-- 字段:
--   id          16 字节 hex(profile 生成时由 admin CLI 随机产生);
--   revoked_at  Unix 秒;
--   reason      自由文本(留给运维写「员工离职」「设备丢失」等)。
--
-- 不写 user_id:profile 可以撤销跨用户(虽然典型一对一,但概念上 id 全库唯一)。

CREATE TABLE IF NOT EXISTS revoked_profiles (
    id          TEXT PRIMARY KEY,
    revoked_at  INTEGER NOT NULL,
    reason      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_revoked_profiles_at ON revoked_profiles(revoked_at);
