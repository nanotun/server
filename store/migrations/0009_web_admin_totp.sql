-- 0009_web_admin_totp.sql
--
-- 给 web 后台 admin 账号加 TOTP(Time-based One-Time Password,RFC 6238)二步验证。
--
-- 兼容 Google Authenticator / Microsoft Authenticator / Authy / 1Password 等任意支
-- 持 otpauth://totp/ URI 的客户端。算法固定 HMAC-SHA1 / 30 秒步长 / 6 位码 —— 这是
-- Google Authenticator 的"默认且大多数 app 唯一支持"的组合,故意不开放配置以避免互通
-- 问题。
--
-- 设计原则:可选 + 自助。每个 admin 在「我的账号」页面自助绑定,不强制;未绑定的
-- admin 登录流程完全不变,不影响现有部署。强制的话留给将来一个 app_settings 开关
-- (本迁移不引入)。
--
-- 字段:
--   totp_secret      —— base32(RFC 4648) 编码的 20 字节(160 bit)共享密钥。等于
--                       otpauth URI 里的 secret= 字段。明文存(SQLite 文件本身由
--                       root:600 保护,加密层后续可上 envelope 加密;现在不上)。
--                       禁用 TOTP 时清空字符串。
--   totp_enabled     —— 0/1。0 = 没绑或绑到一半;1 = 已经"输入过一次正确码"确认绑
--                       定。登录路径只看这个字段决定是否要求二步;totp_secret 非空
--                       但 enabled=0 = 半成品状态(开始 setup 但没确认),下次 setup
--                       覆盖即可。
--   totp_enabled_at  —— 确认绑定的 unix 秒;只用于审计 / 显示「已启用 X 天」。0 =
--                       未启用。
--
-- 备份恢复码:web_admin_recovery_codes 表
--   admin 启用 TOTP 时一次性生成 10 个一次性恢复码(每条 10 位 base32,4+1+5 分组
--   方便手抄)。明文只在生成时显示一次,数据库只存 argon2id 哈希。用过一次即作废
--   (used_at != 0)。重新生成会作废全部旧码并发新的 10 个。
--   如果 admin 丢手机,可以拿一条恢复码登录;登录后建议立刻 disable + 重绑 + 重新
--   生成恢复码。

PRAGMA foreign_keys = ON;

ALTER TABLE web_admins ADD COLUMN totp_secret     TEXT    NOT NULL DEFAULT '';
ALTER TABLE web_admins ADD COLUMN totp_enabled    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE web_admins ADD COLUMN totp_enabled_at INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS web_admin_recovery_codes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id    INTEGER NOT NULL REFERENCES web_admins(id) ON DELETE CASCADE,
    -- argon2id PHC 编码;与 web_admins.password_hash 同算法(auth/psk.go EncodePSK)。
    -- 校验时遍历该 admin 的未使用恢复码逐个 argon2id verify,N=10,慢一点没关系
    -- ——一次性使用 + admin 角色操作低频。
    code_hash   TEXT    NOT NULL,
    -- used_at = 0 时可用;> 0 表示已使用,used_ip 留作审计现场。
    used_at     INTEGER NOT NULL DEFAULT 0,
    used_ip     TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL
);

-- 按 admin 查找未使用恢复码的常用查询,加索引避免全表扫;数据量很小但仍建好习惯。
CREATE INDEX IF NOT EXISTS idx_web_admin_recovery_admin
    ON web_admin_recovery_codes(admin_id, used_at);
