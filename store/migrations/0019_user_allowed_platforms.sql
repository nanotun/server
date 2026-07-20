-- 0019 (2026-07-18):users 表加 allowed_platforms —— 「按用户限制可登录平台」白名单。
--
-- 设计:
--   allowed_platforms  TEXT  逗号分隔的 canonical 平台 token
--                            (macos/ios/android/windows/linux/router)。
--
--   NULL / 空串 = **不设限**:任何平台(含客户端未上报 platform)一律放行。
--   存量老 user 迁移后全是 NULL → 行为与迁移前完全一致(向后兼容);默认新建 user
--   也不带该字段 → 同样不设限。只有管理员显式设了非空白名单,登录时才按
--   store.User.AllowsPlatform 精确匹配,不命中 → 服务端回 CodePlatformNotAllowed(910),
--   客户端把它当终止码(停连、不清 token、提示「此账号不支持在当前平台使用」)。
--
-- 与 exit_allowed 关系:同为 user 级策略字段,但平台白名单额外提供 update 入口
-- (nanotun-admin user set-platforms / web 编辑),exit_allowed 仍只能建号时设。
--
-- **策略拒绝,非安全边界**:platform 由客户端自报(编译期写死 / std::env::consts::OS),
-- 技术用户可伪造 —— 仅用于计费 / 分级。登录路径读它(auth 校验),不影响 argon2 校验。

PRAGMA foreign_keys = ON;

ALTER TABLE users ADD COLUMN allowed_platforms TEXT;
