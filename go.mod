module github.com/nanotun/server

go 1.25.0

require (
	github.com/apernet/hysteria/core/v2 v2.6.3
	github.com/apernet/hysteria/extras/v2 v2.6.3
	github.com/cloudflare/circl v1.6.3
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/mdp/qrterminal/v3 v3.2.1
	github.com/pelletier/go-toml/v2 v2.2.4
	github.com/prometheus-community/pro-bing v0.8.0
	github.com/sirupsen/logrus v1.9.4
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/vishvananda/netlink v1.3.0
	github.com/xtaci/kcp-go/v5 v5.6.72
	github.com/xtaci/smux v1.5.55
	github.com/xtls/reality v0.0.0-20260322125925-9234c772ba8f
	golang.org/x/crypto v0.48.0
	golang.org/x/net v0.50.0
	golang.org/x/sync v0.20.0
	golang.org/x/sys v0.42.0
	golang.org/x/time v0.14.0
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
	modernc.org/sqlite v1.50.1
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/apernet/quic-go v0.52.1-0.20250607183305-9320c9d14431 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/pprof v0.0.0-20250317173921-a4b03ec1a45e // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/klauspost/reedsolomon v1.12.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/pires/go-proxyproto v0.11.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/stretchr/testify v1.10.0 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go.uber.org/mock v0.5.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/term v0.40.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	golang.org/x/tools v0.42.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.72.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	rsc.io/qr v0.2.0 // indirect
)

replace github.com/xtls/reality v0.0.0-20260322125925-9234c772ba8f => ./third_party/xtls-reality
