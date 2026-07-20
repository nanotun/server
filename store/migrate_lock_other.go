//go:build windows || plan9

package store

// acquireMigrateLock 在 windows / plan9 上退化为 noop。
//
// 取舍:nanotun 的部署目标只有 linux(server)和 darwin(开发机本地测试),不会
// 同时在 windows 跑两份 nanotun-admin 互相覆盖迁移。Windows 上不实现 flock 是
// 为了避免引入 golang.org/x/sys/windows 这个额外依赖。
func acquireMigrateLock(dbPath string) (func(), error) {
	return func() {}, nil
}
