-- 0028_port_forwards_uuid_index.sql
--
-- 为 port_forwards.target_device_uuid 加索引(第四轮深扫 MED,store #17,性能)。
--
-- 端口转发管理器在「设备上线 / 下线、reload、建连」时按 target_device_uuid 反查其映射,以决定要不要
-- 启停对应 public_port 监听。port_forwards 上此前只有 public_port 的 UNIQUE 索引,按 target_device_uuid
-- 的查询退化为全表扫。映射数一般不大,但每次设备状态变化都会触发,加一个单列索引即消除线性扫描,
-- 与 0026(devices.device_uuid)同一动机。
--
-- 非唯一:一台设备可映射多个 public_port,故普通索引,不改变唯一性语义。DROP+CREATE 语义幂等。

CREATE INDEX IF NOT EXISTS idx_port_forwards_target_uuid ON port_forwards(target_device_uuid);
