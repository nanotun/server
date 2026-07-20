-- nanotun schema v18 — FRP 式反向端口转发映射
--
-- 表 port_forwards：外部公网访问 server 的 public_port（TCP），由 server 转发到 mesh 节点自身端口，或其
-- LAN 后设备。相当于 frp 的反向代理（internet → server:public_port → mesh 内部目标）。
--
-- 字段:
--   public_port        : server 上对公网监听的 TCP 端口（UNIQUE，一端口一映射）。
--   proto              : 目前仅 'tcp'（保留列，便于将来扩 udp）。
--   target_device_uuid : 目标所属 mesh 设备 UUID（node 目标 = 该设备本身；LAN 目标 = 该 LAN 的宣告方设备）。
--   target_ip          : 转发目的 IP（node 目标 = 设备 vIP；LAN 目标 = 设备 LAN 后某 IP，须在其已批准宣告网段内）。
--   target_port        : 目的端口。
--   enabled            : 1=启用监听；0=保留配置但不监听。
--   comment            : 备注（可空）。
--   created_at         : 创建时刻 Unix 秒。
--
-- 说明：不设 device_id 外键——目标设备离线/未注册时映射仍可保留（与 exit/subnet「离线可选」语义一致），
-- 由 server 端口转发管理器在启监听/建连时按 UUID 实时解析当前会话与 vIP。

CREATE TABLE IF NOT EXISTS port_forwards (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    public_port        INTEGER NOT NULL UNIQUE,
    proto              TEXT    NOT NULL DEFAULT 'tcp',
    target_device_uuid TEXT    NOT NULL,
    target_ip          TEXT    NOT NULL,
    target_port        INTEGER NOT NULL,
    enabled            INTEGER NOT NULL DEFAULT 1,
    comment            TEXT    NOT NULL DEFAULT '',
    created_at         INTEGER NOT NULL DEFAULT 0
);
