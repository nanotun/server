-- nanotun schema v1
-- 自托管模式下 nanotun 不再依赖 旧的集中式后端会话授权，需要在本地保存
-- 用户、设备、vIP 租约和 ACL 等状态。表结构按「最小可用 + 给未来企业版留位」设计。

PRAGMA foreign_keys = ON;

-- 应用全局元数据：schema 版本、初始化向导是否完成、默认 vIP 网段等
CREATE TABLE IF NOT EXISTS app_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- nanotun 用户账号（独立账号体系）
-- 一个 nanotun 可由多名用户登录使用，每名用户可绑定多台设备。
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    -- argon2id 编码后的 PSK 字符串，格式见 auth/psk.go：
    -- argon2id$v=19$m=65536,t=2,p=4$<base64-salt>$<base64-hash>
    psk_hash        TEXT NOT NULL,
    is_admin        INTEGER NOT NULL DEFAULT 0,

    -- 管理员可手动给某个 user 钉一个固定 vIP（v4 / v6 各一个），登录时优先使用。
    -- 注意：固定 vIP 仍受网段约束；为空表示由系统自动分配。
    fixed_vip_v4    TEXT,
    fixed_vip_v6    TEXT,

    -- 单位：bps；0 / NULL 表示不限。M0 仅落库，未投入限速使用。
    bandwidth_up_bps   INTEGER NOT NULL DEFAULT 0,
    bandwidth_down_bps INTEGER NOT NULL DEFAULT 0,

    -- 是否允许该用户把 nanotun 当出口网关（exit node）。M0 仅落库。
    exit_allowed    INTEGER NOT NULL DEFAULT 1,

    -- 预留给企业版：role/sso_provider/sso_subject。
    role            TEXT NOT NULL DEFAULT 'user',
    sso_provider    TEXT,
    sso_subject     TEXT,

    created_at      INTEGER NOT NULL,
    disabled_at     INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_sso ON users(sso_provider, sso_subject)
    WHERE sso_provider IS NOT NULL AND sso_subject IS NOT NULL;

-- 客户端设备：客户端在登录帧里上报 device_uuid + device_name。
-- (user_id, device_uuid) 全局唯一；同一用户在同一台设备上重复登录沿用同一行。
CREATE TABLE IF NOT EXISTS devices (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_uuid   TEXT NOT NULL,
    device_name   TEXT NOT NULL DEFAULT '',
    platform      TEXT NOT NULL DEFAULT '',
    last_seen_at  INTEGER NOT NULL,
    created_at    INTEGER NOT NULL,
    UNIQUE(user_id, device_uuid)
);

CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);

-- vIP 租约：登录时为 device 持久化分配 vIP，下次重连优先沿用。
-- 一台设备至多保留一个 v4 + 一个 v6；manual=1 表示由管理员手动指定，分配器不会改写。
CREATE TABLE IF NOT EXISTS leases (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    INTEGER NOT NULL UNIQUE REFERENCES devices(id) ON DELETE CASCADE,
    vip_v4       TEXT,
    vip_v6       TEXT,
    manual       INTEGER NOT NULL DEFAULT 0,
    assigned_at  INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_leases_vip_v4 ON leases(vip_v4) WHERE vip_v4 IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_leases_vip_v6 ON leases(vip_v6) WHERE vip_v6 IS NOT NULL;

-- 用户级 ACL：仅当 (src_user_id -> dst_user_id) 存在记录时，src 才能访问 dst。
-- src/dst 任一端为 NULL 时表示通配（M0 暂不使用通配，预留给后续 tag-based ACL）。
CREATE TABLE IF NOT EXISTS acl_pairs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    src_user_id   INTEGER REFERENCES users(id) ON DELETE CASCADE,
    dst_user_id   INTEGER REFERENCES users(id) ON DELETE CASCADE,
    -- 'allow' | 'deny'，预留 'log' 等。
    action        TEXT NOT NULL DEFAULT 'allow',
    created_at    INTEGER NOT NULL,
    UNIQUE(src_user_id, dst_user_id, action)
);

-- 给企业版预留：标签可挂在 user 上，未来支持 tag-based ACL。
CREATE TABLE IF NOT EXISTS user_tags (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tag        TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(user_id, tag)
);

-- 审计日志（M0 不写，但 schema 先就位，避免后续迁移）
CREATE TABLE IF NOT EXISTS audit_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL,
    detail     TEXT,
    at         INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_logs(at);

-- 默认元数据
INSERT OR IGNORE INTO app_settings(key, value) VALUES
    ('schema_version', '1'),
    ('setup_completed', '0'),
    ('default_cidr_v4', '100.64.0.0/24'),
    ('default_cidr_v6', '');
