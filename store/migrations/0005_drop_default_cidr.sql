-- nanotun schema v5 — 清理未用的 app_settings 键
--
-- 背景:0001_init.sql 在最早版本里预写了 default_cidr_v4 / default_cidr_v6,
-- 设想用 DB-driven 的网段配置替代 [tun].subnets。实际从未接入数据面 ——
-- VIP 分配始终读 config.toml 的 [tun].subnets / subnets_v6,这两条 setting
-- 一直是「写了不读」的悬挂状态。
--
-- 决策(P3-c,2026-05-22):删除而非接入。原因:
--   1. 网段切换必然要求所有客户端重连 + 重新协商 vIP,本质 restart 操作,
--      没有「热改 DB 立即生效」的工程价值;
--   2. config.toml 已经是网段的单一真源,DB 兜底反而制造「两份配置不一致」的运维陷阱;
--   3. 留着会让未来想复用这两个 key 名的人困惑(到底是历史包袱还是有效配置?)
--
-- DELETE 用 OR IGNORE 风格(已不存在不报错),让二次跑或新部署都安全。

DELETE FROM app_settings WHERE key IN ('default_cidr_v4', 'default_cidr_v6');
