# 服务端 TUN 持久化（15 个虚拟网卡）

固定分配三段，每段 5 个，共 15 个 TUN：这样无论局域网是 10、192 还是 172，顶多冲突其中一段，另外两段仍可用。

| 设备 | 网段 | 服务端 IP |
|------|------|-----------|
| tun0–tun4 | 10.0.0.0/24 ~ 10.0.4.0/24 | 10.0.0.1 … 10.0.4.1 |
| tun5–tun9 | 192.168.100.0/24 ~ 192.168.104.0/24 | 192.168.100.1 … 192.168.104.1 |
| tun10–tun14 | 172.16.0.0/24 ~ 172.20.0.0/24 | 172.16.0.1 … 172.20.0.1 |

已存在的 TUN 不会重复创建。

## 玩家间隔离（系统层面）

要求：**一个玩家一个虚拟 IP，同一网段内玩家之间也不能互访**。可在系统层用 iptables + ipset 做“玩家 IP ↔ 玩家 IP”丢包，只保留“玩家 ↔ 网关/公网”。

```bash
# 启用隔离（需 root，且已安装 ipset）
./tun-isolate.sh

# 取消隔离
./tun-isolate-teardown.sh
```

依赖：`iptables`、`ipset`（多数发行版已带；若无则 `apt install ipset` / `yum install ipset`）。  
**隔离已并入 tun-setup**：若已安装 `nanotun-tun-isolate.sh`，每次执行 tun-setup（含开机）时会自动做隔离；取消隔离用 `tun-isolate-teardown.sh`。

## 安装（一次性）

在服务器上执行：

```bash
# 1. 复制脚本并赋予执行权限（两个都装则开机自动建 TUN + 玩家隔离）
cp tun-setup.sh /usr/local/bin/nanotun-tun-setup.sh
cp tun-isolate.sh /usr/local/bin/nanotun-tun-isolate.sh
chmod +x /usr/local/bin/nanotun-tun-setup.sh /usr/local/bin/nanotun-tun-isolate.sh

# 2. 安装并启用 systemd 服务（只用一个 service）
#    单元名统一 nanotun- 前缀,与 install-self-hosted.sh 的标准安装一致;
#    tun-isolate.service 的 After=/Requires= 也指向这个名字。
cp tun-setup.service /etc/systemd/system/nanotun-tun-setup.service
systemctl daemon-reload
systemctl enable nanotun-tun-setup.service
systemctl start nanotun-tun-setup.service

# 3. 检查（应看到 tun0–tun14，且隔离规则已生效）
ip addr show tun0 tun1 tun2 tun3 tun4 tun5 tun6 tun7 tun8 tun9 tun10 tun11 tun12 tun13 tun14
iptables -L INPUT -n -v | head -5
```

之后每次开机会自动创建并配置上述 15 个 TUN。程序里按需打开 `tun0` … `tun14` 即可。

## 删除虚拟网卡

需要卸掉所有 TUN 时，可执行删除脚本（需 root）：

```bash
./tun-teardown.sh
# 若已复制到 /usr/local/bin：
# /usr/local/bin/nanotun-tun-teardown.sh
```

## 修改网段或数量

编辑 `/usr/local/bin/nanotun-tun-setup.sh` 中的循环与网段。若需先删除再重建（会断已有连接），可先执行上面的 `tun-teardown.sh`，再执行：

```bash
/usr/local/bin/nanotun-tun-setup.sh
# 或
systemctl restart nanotun-tun-setup.service
```
