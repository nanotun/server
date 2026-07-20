-- 0010_sync_leases_manual.sql
--
-- 把 leases.manual 与 devices.fixed_vip_v4/v6 一次性对齐。
--
-- 背景:0008 起「固定 vIP」从 user 搬到 device,正常路径下 alloc_lease.go 在客户端
-- 登录时会按 device.fixed_vip_* == lease.vip_* 把 manual 翻成 1。但有几类历史数据
-- 会跑歪:
--   (1) 管理员先创建 device + lease,然后才设 device.fixed_vip_*,在客户端下次
--       登录之前,leases.manual 还停留在 0 ——— UI 上 /leases 列展示"manual=✗"
--       与「已绑定固定 vIP」语义不一致;
--   (2) 旧版 SetDeviceFixedVIP 实现不联动 leases.manual(2026-05-23 之前)所有
--       已部署实例都是这个状态;
--   (3) 反过来:device 的 fixed_vip 后来被清掉,但 leases.manual 还是 1 → 该
--       lease 永远不会被 lease_gc 回收,挂着浪费 vIP 池。
--
-- 用单条 CASE 一次性归一化:
--   - lease.vip_v4 == device.fixed_vip_v4 OR lease.vip_v6 == device.fixed_vip_v6
--     → manual = 1
--   - 否则                                                   → manual = 0
--
-- 之后(2026-05-23 起)store.SetDeviceFixedVIP 自带同步,本 migration 只解决"已
-- 经歪掉的存量"。新建 lease + 改 fixed_vip 都会自动维持一致。

UPDATE leases
   SET manual = CASE
       WHEN EXISTS (
           SELECT 1 FROM devices d
            WHERE d.id = leases.device_id
              AND (
                  (d.fixed_vip_v4 IS NOT NULL AND d.fixed_vip_v4 <> '' AND d.fixed_vip_v4 = leases.vip_v4)
               OR (d.fixed_vip_v6 IS NOT NULL AND d.fixed_vip_v6 <> '' AND d.fixed_vip_v6 = leases.vip_v6)
              )
       ) THEN 1
       ELSE 0
   END;
