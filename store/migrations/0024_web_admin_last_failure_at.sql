-- 0024_web_admin_last_failure_at.sql
--
-- 修 web 管理员锁定「跨 IP、事实上永久」的 DoS(第三轮深扫 M1)。
--
-- 背景:failed_logins 是**只增**计数器,仅在登录成功 / 改密 / 手动 ResetWebAdminLockout 时清零,
-- 没有任何时间衰减。RecordWebAdminLoginFailure 在 `failed_logins >= max_failures` 时把 locked_until
-- 设为 now+lock_seconds;锁定期内 AttemptLogin 提前返回(不记数),但窗口一过 failed_logins 仍 ≥ 阈值,
-- 于是**下一次失败(哪怕只有 1 次)立即重新锁定整个 lock_seconds**。锁只按 admin.id(用户名),不看来源 IP。
-- 结果:只知道某管理员用户名的匿名攻击者,每个锁定窗口投 1 次失败登录,就能让该账号(乃至全部账号)
-- 永久登不进控制台。
--
-- 处理:新增 last_failure_at 列记录「最近一次失败时刻」。RecordWebAdminLoginFailure 改成滑动窗口:
-- 若距上次失败已超过 lock_seconds(窗口),先把计数**衰减归零**再 +1 —— 这样锁定窗口过后单次失败
-- 只让计数回到 1(远低于阈值),不再触发重锁;攻击者必须在一个窗口内重新累积满 max_failures 次失败
-- 才能再次锁定,配合每次尝试的自适应 PoW + 验证码,持续压制的成本大幅提高。合法用户在窗口过后
-- 用正确密码登录即恢复(成功路径本就清零)。
--
-- 默认 0 = 从未失败过;幂等(列不存在才加,但 ALTER 无 IF NOT EXISTS,迁移框架保证每个版本只跑一次)。

ALTER TABLE web_admins ADD COLUMN last_failure_at INTEGER NOT NULL DEFAULT 0;
