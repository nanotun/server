package util

// DefaultVPNWebSocketPath 为 [server].vpn_websocket_path 未配置时的默认路径（须与客户端默认一致）。
// 生产环境应在 [server].vpn_websocket_path 里配置你自己的随机长路径（客户端 profile 会自动带上），
// 不要依赖这个公开的内置默认值——它只是让本地快速试跑能工作。
const DefaultVPNWebSocketPath = "/internal/nanotun/data-plane/ws/v1/77fbc7cc617ecb083e6e2c87b1699a993366c3d6"
