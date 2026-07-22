-- 0026_devices_uuid_index.sql
--
-- 为 GetDeviceByUUIDAny 加索引(第三轮深扫 L11,性能)。
--
-- GetDeviceByUUIDAny 按 `WHERE device_uuid=? ORDER BY last_seen_at DESC, id DESC` 查询,给「只握有
-- UUID、不知 user」的调用方用(端口转发按 target_device_uuid 运行时解析 vIP)。既有索引只有复合
-- UNIQUE(user_id, device_uuid) 与 idx_devices_user(user_id),device_uuid 都不是**最左列**,故该查询
-- 退化为全表扫 + 排序,O(N)。调用点低频(reload / 连接建立,非每包),影响有限,但加一个单列索引即消除。
--
-- 非唯一索引:device_uuid 全局唯一只是客户端惯例、非 schema 强制((user_id, device_uuid) 才是 UNIQUE),
-- 故这里用普通索引,不改变唯一性语义。

CREATE INDEX IF NOT EXISTS idx_devices_uuid ON devices(device_uuid);
