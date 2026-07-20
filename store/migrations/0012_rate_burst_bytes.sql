-- 0012 (2026-05-23):rate.Limiter burst 提到 app_settings 让运维可调。
--
-- 历史(0011):rate.Limiter burst 在 server 端写死 64 KiB。该值是 hy2/REALITY 现网
-- 经验的折中,但对短突发流量友好型业务(VoIP / 浏览首屏)偏小,SRE 没旋钮可调。
--
-- 设计:
--   rate_burst_bytes:rate.Limiter 的 burst(令牌桶容量),字节。
--   0 / 缺失 = 沿用代码内 default(64 KiB),保留向下兼容。
--   合法值的下限由 server 端兜底(实测过小会让 limiter wait 抖动剧烈,设 4 KiB 下限)。
--
-- 与限速 cap 关系:burst 不改稳态吞吐(rate),只改瞬时突发能力(单次最多放 burst 字节,
-- 之后按 rate 速率匀给)。设大 → 突发友好;设小 → shaping 更严苛。
--
-- 热更行为:settings 改完调 control sock /rate/refresh,server 端调 limiter.SetBurst(),
-- 已有 token 状态保留 → 客户端感知不到链路抖动。

PRAGMA foreign_keys = ON;

INSERT OR IGNORE INTO app_settings(key, value) VALUES
    ('rate_burst_bytes', '0');
