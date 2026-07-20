-- nanotun schema v17 — 4via6 站点 ID（SR-VIA6）
--
-- 表 via6_sites：给每个「子网路由器（宣告方）设备」分配一个稳定的 16 位 site_id，用于 4via6 地址消歧——
-- 多个宣告方宣告同一 RFC1918 网段（如都是 192.168.1.0/24）时，用 (siteID, 原始 IPv4) 编码进唯一的
-- IPv6 地址（见 cmd/nanotund/via6.go），使用方本地 v4 与远端各站点的 v6 地址不重叠 → 可同时访问。
--
-- 字段:
--   site_id   : AUTOINCREMENT 主键,从 1 单调递增、删除不复用(靠 sqlite_sequence 保证跨会话/重启稳定,
--               不会把旧站点的 4via6 地址错映射到新设备)。取值须 ≤ 65535(16 位);正常部署设备数远小于此。
--   device_id : devices.id 外键,级联删除;UNIQUE 保证一设备一 site_id。
--   created_at: 分配时刻 Unix 秒。
--
-- per-device(非 per-route):一个宣告方设备 = 一个「站点」,它宣告的多条 CIDR 共享同一 site_id,
-- 4via6 地址靠低 32 位的原始 IPv4 区分站点内主机。

CREATE TABLE IF NOT EXISTS via6_sites (
    site_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER NOT NULL UNIQUE,
    created_at INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);
