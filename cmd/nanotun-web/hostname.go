package main

import (
	"net"
	"os"
)

// hostnameOS / lookupAddrOS:主机名的两个来源,写成变量而非函数只为可测性,
// 生产恒为 os.Hostname / net.LookupAddr。
//
// 这俩的返回值由宿主机的 /etc/hostname 与 DNS 解析决定,测试进程无法左右:
// 在开发机上反查 127.0.0.1 总能拿到 localhost,在最小容器里又总是失败。
// 而 netHostnameOrLocal 的三级兜底(反查 → os.Hostname → "localhost")正是
// 要在这些环境之间保证「永远给得出一个非空名字」—— 这个名字会进自签证书的
// SAN 与页面标题,空串会产出一张谁也验不过的证书。留接缝才能把三级都验一遍。
var (
	hostnameOS   = os.Hostname
	lookupAddrOS = net.LookupAddr
)
