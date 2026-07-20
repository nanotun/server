-- nanotun schema v6 — subnet route advertise (P2#12)
--
-- 表 subnet_routes:每一行 = 一条 (device, CIDR) 路由声明,等管理员审批后允许该
-- device 向其它 peers 转发该 CIDR 流量。
--
-- 字段:
--   device_id    : devices.id 外键(级联删除);路由跟着 device 走。
--   cidr         : 归一化后的 CIDR 文本(util.NormalizeAdvertisedCIDR 处理过)。
--                  同 device 多个 cidr 走多行;不同 device 声明同一 cidr 也合法
--                  (admin 可以分别批,数据面在转发时按某种优先级选 device)。
--   status       : 'pending' / 'approved' / 'rejected',与 util.RouteStatus* 对齐。
--   advertised_at: 最近一次客户端上报的 Unix 秒。
--   approved_at  : 审批通过的 Unix 秒(approve 路径写,reject/重新 advertise 清空)。
--   reason       : reject 时由 admin 填的原因(空串否则)。
--
-- UNIQUE(device_id, cidr) 保证同 device 同 cidr 唯一一行;客户端重复 advertise
-- 走 INSERT ... ON CONFLICT 路径更新 advertised_at,不改 status。

CREATE TABLE IF NOT EXISTS subnet_routes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     INTEGER NOT NULL,
    cidr          TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'pending',
    advertised_at INTEGER NOT NULL DEFAULT 0,
    approved_at   INTEGER NOT NULL DEFAULT 0,
    reason        TEXT    NOT NULL DEFAULT '',
    UNIQUE(device_id, cidr),
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_subnet_routes_status ON subnet_routes(status);
CREATE INDEX IF NOT EXISTS idx_subnet_routes_device ON subnet_routes(device_id);
