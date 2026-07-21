package store

import (
	"context"
	"fmt"
	"strconv"
)

// 全局默认带宽限速(0011, 2026-05-23)。
//
// 存于 app_settings:
//   rate_default_upload_bps   字节/秒,0 = 沿用 toml [server].upload_rate
//   rate_default_download_bps 字节/秒,0 = 沿用 toml [server].download_rate
//
// 与 device.rate_*_bps 关系详见 store/migrations/0011_devices_rate_limit.sql。
// web 后台 / nanotun-admin CLI 都通过本组函数读写,server 在登录路径 + control sock
// /rate/refresh 两条路径都会读最新值。

const (
	settingRateDefaultUploadBPS   = "rate_default_upload_bps"
	settingRateDefaultDownloadBPS = "rate_default_download_bps"
	settingRateBurstBytes         = "rate_burst_bytes"
)

// RateBurstBytesMin/Max 是 rate_burst_bytes 的有效区间(byte),= 数据面 effectiveBurst 的 clamp
// 边界的**单一真源**。0 = 用代码默认(64 KiB)。cmd/nanotund 的 effectiveBurst 引用这两个常量,
// 一个对齐测试(TestRateBurstBoundsMatchStore)钉住两侧不漂移。深扫第十二轮 MED:此前写校验
// 只查「非负」,运行期却把 (0,4KiB) 夹到 4KiB、>16MiB 夹到 16MiB,运维设的小/大 burst 被静默改。
const (
	RateBurstBytesMin int64 = 4 * 1024
	RateBurstBytesMax int64 = 16 * 1024 * 1024
)

// RateDefaults 全局默认带宽限速快照(byte/sec)+ burst 容量(byte)。
//
// 0 = 「该方向 / 该层不在 settings 层做强制」,登录路径会继续回退 toml / 代码 default;
// 任意一方向都允许独立设置(只限上行或只限下行)。BurstBytes=0 时 server 用代码 default(64 KiB)。
type RateDefaults struct {
	UploadBPS   int64
	DownloadBPS int64
	// BurstBytes 0012(2026-05-23):rate.Limiter burst 旋钮。
	// 0 / 缺失 = 沿用代码 default;>0 = 全局覆盖(server 兜底下限 4 KiB)。
	// 与 UploadBPS/DownloadBPS 独立,改其中之一不影响另外两个。
	BurstBytes int64
}

// GetRateDefaults 读出全局默认限速 + burst。键不存在时返回零值(语义 = 不限/沿用 default)。
//
// 容错:value 解不出 int64 时按 0 处理但不报错 —— migration 已经 INSERT OR IGNORE 写入
// 字符串 '0',只有运维手抠 DB 写歪才会触发,稳态运行不应丢弃健康 server 的请求。
func (s *Store) GetRateDefaults(ctx context.Context) (RateDefaults, error) {
	up, err := s.settingsGetInt64(ctx, settingRateDefaultUploadBPS)
	if err != nil {
		return RateDefaults{}, fmt.Errorf("store: read %s: %w", settingRateDefaultUploadBPS, err)
	}
	down, err := s.settingsGetInt64(ctx, settingRateDefaultDownloadBPS)
	if err != nil {
		return RateDefaults{}, fmt.Errorf("store: read %s: %w", settingRateDefaultDownloadBPS, err)
	}
	burst, err := s.settingsGetInt64(ctx, settingRateBurstBytes)
	if err != nil {
		return RateDefaults{}, fmt.Errorf("store: read %s: %w", settingRateBurstBytes, err)
	}
	return RateDefaults{UploadBPS: up, DownloadBPS: down, BurstBytes: burst}, nil
}

// SetRateDefaults 持久化全局默认限速 + burst。三个字段必须同时给值,语义清晰:
//   - 想「只清除上行」就传 (0, currentDown, currentBurst);
//   - 想「双向都清」传 (0, 0, currentBurst);
//   - 想「burst 回 default」传 (..., ..., 0)。
//
// 负数视为非法 → ErrInvalid。
func (s *Store) SetRateDefaults(ctx context.Context, d RateDefaults) error {
	if d.UploadBPS < 0 || d.DownloadBPS < 0 || d.BurstBytes < 0 {
		return fmt.Errorf("store: rate defaults must be >= 0 (got up=%d down=%d burst=%d): %w",
			d.UploadBPS, d.DownloadBPS, d.BurstBytes, ErrInvalid)
	}
	// 深扫第九轮 LOW:三个键包进一个事务原子写入。此前是三次独立 autocommit,中途
	// 失败 / 崩溃会留下「上行已改、下行没改」的撕裂态,且 MaxOpenConns>1 时并发读者
	// 可能读到中间态。事务保证要么三个全改、要么全不改。
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: set rate defaults begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	setOne := func(key, val string) error {
		if _, e := tx.ExecContext(ctx,
			`INSERT INTO app_settings(key,value) VALUES(?,?)
			 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, val); e != nil {
			return fmt.Errorf("store: set %s: %w", key, e)
		}
		return nil
	}
	if err := setOne(settingRateDefaultUploadBPS, strconv.FormatInt(d.UploadBPS, 10)); err != nil {
		return err
	}
	if err := setOne(settingRateDefaultDownloadBPS, strconv.FormatInt(d.DownloadBPS, 10)); err != nil {
		return err
	}
	if err := setOne(settingRateBurstBytes, strconv.FormatInt(d.BurstBytes, 10)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: set rate defaults commit: %w", err)
	}
	return nil
}

// ValidateNonNegativeInt64Setting 校验一个 app_settings value 是可解析的非负 int64。
// 深扫第十一轮 MED:用于 CLI raw `setting set` 对 rate_default_* / rate_burst_bytes 做写入兜底。
// 否则 `setting set rate_default_upload_bps notanumber` 落库后被 settingsGetInt64 静默当 0
// (= 不限速),与运维「设一个限速」的本意相反,且没有任何报错。
//
// 刻意**不 TrimSpace** —— 必须与读路径 settingsGetInt64 的 strconv.ParseInt(v)(同样不 trim)
// 逐字一致:否则 " 42 " 能通过写校验落库,读时却被 ParseInt 判失败静默当 0,重演本轮
// mesh 那类「写校验放行、读路径解不出」的不一致。带空白 = 误配,直接拒。
func ValidateNonNegativeInt64Setting(v string) error {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fmt.Errorf("must be a non-negative integer with no surrounding spaces, got %q", v)
	}
	if n < 0 {
		return fmt.Errorf("must be >= 0, got %d", n)
	}
	return nil
}

// ValidateRateBurstSetting 校验 rate_burst_bytes 的写入值。深扫第十二轮 MED:与运行期
// effectiveBurst 的 clamp 对齐 —— 只接受 0(= 用代码默认 64 KiB)或落在 [RateBurstBytesMin,
// RateBurstBytesMax] 的值。落在 (0, min) 或 > max 的值运行期会被静默夹住,与运维本意不符,
// 直接拒并给出区间提示。同样刻意不 TrimSpace,与读路径 settingsGetInt64 的 ParseInt 对齐。
func ValidateRateBurstSetting(v string) error {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fmt.Errorf("must be an integer with no surrounding spaces, got %q", v)
	}
	if n == 0 {
		return nil // 0 = 用代码默认(64 KiB)
	}
	if n < RateBurstBytesMin || n > RateBurstBytesMax {
		return fmt.Errorf("must be 0 (use default) or within [%d, %d] bytes, got %d",
			RateBurstBytesMin, RateBurstBytesMax, n)
	}
	return nil
}

// settingsGetInt64:value 不存在返回 0; 存在但解析失败也返回 0,error 仅在 DB 层报错时返回。
// 「不存在 vs 解析失败」对调用方语义等价(都 = 不限),不区分简化上层。
func (s *Store) settingsGetInt64(ctx context.Context, key string) (int64, error) {
	v, ok, err := s.SettingsGet(ctx, key)
	if err != nil {
		return 0, err
	}
	if !ok || v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, nil
	}
	return n, nil
}
