-- 0020 (2026-07-19):devices 表加 alias —— 管理员起的「别名/展示名」。
--
-- 背景:device_name 的所有权在客户端 —— 每次登录 UpsertDevice 都用客户端上报的
-- 主机名覆盖,管理端改了也会被冲回去。出口节点在客户端下拉里显示的就是这个名字,
-- 运维想叫它 "sg-exit" 而不是 "GL-MT3000"。
--
-- 设计(alias 与上报名并存,互不干扰):
--   alias  TEXT NOT NULL DEFAULT ''   管理员显式设置;'' = 未设。
--
--   - UpsertDevice(登录路径)**不写 alias 列** → 客户端上报名照常刷新,alias 永不被覆盖;
--   - 展示/下发(exits-list、routes-list、web 各页)取 Device.DisplayName():alias 非空用 alias,
--     否则回落 device_name —— wire 字段仍是 ExitInfo.DeviceName,老客户端零改动;
--   - MagicDNS 主机名**仍基于 device_name**(客户端自己知道自己叫什么),alias 只管人眼。
--   - 不强制唯一:纯展示用,撞名无功能影响。

PRAGMA foreign_keys = ON;

ALTER TABLE devices ADD COLUMN alias TEXT NOT NULL DEFAULT '';
