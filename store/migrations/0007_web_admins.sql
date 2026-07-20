-- nanotun schema v7 — 独立 Web 后台账号体系。
--
-- 与 users 表完全解耦:VPN 数据面登录走 users.psk_hash,Web 管理后台登录走
-- web_admins.password_hash。两套 argon2id,两套生命周期,两套 audit actor。
-- 设计动机:Web admin 一旦泄露只影响管理面,不会让 attacker 同时获得 VPN 数据面访问权。
--
-- role 取值:
--   'admin'  — 全功能(增删改查 + 触发运行时 reload/kick + 备份)
--   'viewer' — 仅 list/get;所有写操作 403
-- 后续可加 'auditor'(仅看 audit_logs)等。

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS web_admins (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    -- argon2id PHC 编码,与 auth/psk.go EncodePSK 同格式。
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL DEFAULT 'admin',
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      INTEGER NOT NULL,
    -- 谁创建的(NULL = setup 首位 admin 或 SQL 手工)。指向 web_admins.id 自引用。
    created_by      INTEGER REFERENCES web_admins(id) ON DELETE SET NULL,
    last_login_at   INTEGER NOT NULL DEFAULT 0,
    last_login_ip   TEXT    NOT NULL DEFAULT '',
    -- I8:连续登录失败计数 + 锁定截止时间,用于 Web 端简单的暴力破解防护。
    -- argon2id 已经很慢,这里只是辅助:5 次失败锁 15 分钟。0=未锁。
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER NOT NULL DEFAULT 0
);

-- web_sessions:持久化登录会话,server 重启不掉登录,admin 可主动 revoke。
-- session id = 32 字节随机的 base64url(无 padding,43 字符),作为 cookie value;
-- 数据库里只存它(明文),因为 cookie value 等同 bearer token,本身就是 secret。
CREATE TABLE IF NOT EXISTS web_sessions (
    id              TEXT    PRIMARY KEY,
    admin_id        INTEGER NOT NULL REFERENCES web_admins(id) ON DELETE CASCADE,
    created_at      INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    ip              TEXT    NOT NULL DEFAULT '',
    user_agent      TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_web_sessions_admin   ON web_sessions(admin_id);
CREATE INDEX IF NOT EXISTS idx_web_sessions_expires ON web_sessions(expires_at);
