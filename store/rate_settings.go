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
