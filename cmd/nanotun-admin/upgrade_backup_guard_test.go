package main

// upgrade_backup_guard_test.go —— 升级前必须给数据库留一份还原点。
//
// schema 迁移是一路向前的:现有三十来个迁移里有 DROP COLUMN、有改名,跑过去就回不来。
// 而降级守卫(ErrSchemaFromFuture)拦下旧二进制时,给的出路正是「从降级前的备份恢复
// 数据库」—— 在此之前,产品里没有任何一处会产生那份备份。那句话指着一个不存在的东西,
// 而它出现的时机,恰恰是人已经把机器降级、正着急的时候。
//
// 实测过这条路能走通:v0.1.0 装好、灌进 5 个用户,直升当前版本(跨掉三十个迁移里的
// 绝大部分),用户、拨号地址、config 与证书的 sha 全部原样保留 —— 迁移本身是稳的。
// 缺的从来不是正确性,是「万一」时的退路。
//
// 位置有讲究:装机脚本第 1 步装好新二进制,服务要到第 6 步才重启 —— 中间那段是库还停在
// 旧 schema、迁移尚未发生的唯一窗口。挪到第 6 步之后就只剩迁移完的库,备份也就没意义了。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallSelfHosted_BacksUpDBBeforeMigrating(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("../..", "scripts/install-self-hosted.sh"))
	if err != nil {
		t.Fatalf("读 install-self-hosted.sh: %v", err)
	}
	body := string(raw)

	iBackup := strings.Index(body, `backup "$BACKUP_FILE"`)
	iStart := strings.Index(body, `step "6. 启动并设为开机自启"`)
	if iBackup < 0 {
		t.Fatal("升级前没有备份数据库 —— 迁移过去就回不来了,而降级守卫给的出路正是「从备份恢复」")
	}
	if iStart < 0 {
		t.Fatal("找不到第 6 步,这个测试的定位假设已经失效")
	}
	if iBackup > iStart {
		t.Error("备份排在了启动服务之后 —— 那时迁移已经跑完,备下来的是迁移后的库,等于没备")
	}

	// VACUUM INTO 是关键:老服务这会儿还跑着,直接拷文件可能拿到 WAL 中间态。
	// 而 backup 子命令本身不跑 Migrate,所以拿新 admin 备份一个未迁移的库是安全的。
	if !strings.Contains(body, "nanotun-admin --db-path \"$DB_FILE\" backup") {
		t.Error("备份没走 nanotun-admin backup —— 直接 cp 一个正在被写的 SQLite 可能拿到不一致的快照")
	}
	// 全新安装没有库可备,不该在那条路上报错或留空文件。
	if !strings.Contains(body, `if [ -f "$DB_FILE" ]; then`) {
		t.Error("没有先判断库是否存在 —— 全新安装那条路上会凭空报一次备份失败")
	}
	// 不设上限的话每升一次多一份,而这个目录没人会去看,直到磁盘满了才发现。
	if !strings.Contains(body, "tail -n +4") {
		t.Error("备份没有轮转上限 —— 升级次数一多就把磁盘吃满,而症状会表现成「服务起不来」")
	}
	// 备份失败不该把一台已经装到第 4 步的机器丢在半路。
	if !strings.Contains(body, "数据库备份没做成(不影响本次安装,继续)") {
		t.Error("备份失败被当成致命错 —— 它是保险,不是安装的前置条件")
	}
}

func TestSchemaFromFuture_PointsAtRealBackupPath(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("../..", "store/migrations.go"))
	if err != nil {
		t.Fatalf("读 migrations.go: %v", err)
	}
	if !strings.Contains(string(raw), "/var/lib/nanotun/backups/") {
		t.Error("降级守卫没有指出备份的确切位置 —— " +
			"「从降级前的备份恢复」这句话,得让正着急的人知道那份备份在哪、怎么用")
	}
}
