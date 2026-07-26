//go:build !unix

package store

import "io/fs"

// 非 unix 平台(主要是 Windows)拿不到稳定的 dev/ino,直接放弃检测。
// server / web 后台只在 Linux 上部署,这里保持可编译即可。
func sysFileIdentity(fs.FileInfo) (FileIdentity, bool) { return FileIdentity{}, false }
