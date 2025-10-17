# 防火墙使用指南

本文档介绍如何使用 BGO 防火墙的两个核心命令：`firewall-update` 和 `firewall-ratelimit`。

## 快速开始

### 第一步：启动防火墙服务

```bash
# 启动防火墙服务（指定网卡）
sudo ./bin/bgo firewall-server start --interface eth0
```

### 第二步：配置防火墙规则或流量限制

现在可以使用 `firewall-update` 和 `firewall-ratelimit` 命令了！

---

## firewall-update - 防火墙规则管理

### 基本概念

- **XDP 模式**：高性能数据包过滤（在网卡驱动层）
- **TC 模式**：流量控制（支持 ingress/egress 方向）
- **白名单（whitelist）**：只允许匹配的流量通过
- **黑名单（blacklist）**：阻止匹配的流量

### 常用命令

#### 1. 查看所有规则

```bash
# 查看 XDP 规则（白名单+黑名单）
sudo ./bin/bgo firewall-update --xdp --action list

# 只查看白名单规则
sudo ./bin/bgo firewall-update --xdp --type whitelist --action list

# 只查看黑名单规则
sudo ./bin/bgo firewall-update --xdp --type blacklist --action list
```

#### 2. 添加白名单规则

```bash
# 允许来自特定 IP 的 SSH 连接
sudo ./bin/bgo firewall-update --xdp --type whitelist --action add \
  --ip 192.168.1.100 --port 22 --protocol tcp

# 允许整个子网访问 HTTP
sudo ./bin/bgo firewall-update --xdp --type whitelist --action add \
  --ip 192.168.1.0/24 --port 80 --protocol tcp

# 允许特定 IP 的所有流量
sudo ./bin/bgo firewall-update --xdp --type whitelist --action add \
  --ip 10.0.0.5
```

#### 3. 添加黑名单规则

```bash
# 阻止特定 IP
sudo ./bin/bgo firewall-update --xdp --type blacklist --action add \
  --ip 192.168.1.200

# 阻止整个 IP 段
sudo ./bin/bgo firewall-update --xdp --type blacklist --action add \
  --ip 10.0.0.0/8

# 阻止特定 IP 的 UDP 53 端口（DNS）
sudo ./bin/bgo firewall-update --xdp --type blacklist --action add \
  --ip 8.8.8.8 --port 53 --protocol udp
```

#### 4. 删除规则

```bash
# 先查看规则索引
sudo ./bin/bgo firewall-update --xdp --type whitelist --action list

# 删除索引为 0 的白名单规则
sudo ./bin/bgo firewall-update --xdp --type whitelist --action remove --index 0

# 删除索引为 1 的黑名单规则
sudo ./bin/bgo firewall-update --xdp --type blacklist --action remove --index 1
```

#### 5. 查看统计信息

```bash
# 查看 XDP 防火墙统计
sudo ./bin/bgo firewall-update --xdp --action stats
```

输出示例：
```
Firewall Statistics:
Total Packets:   15234
Allowed Packets: 14856
Blocked Packets: 378
Allow Rate:      97.52%
Block Rate:      2.48%
```

### TC 模式（流量控制）

TC 模式支持区分入站（ingress）和出站（egress）流量。

#### Ingress（入站流量）规则

```bash
# 允许特定 IP 的入站 SSH
sudo ./bin/bgo firewall-update --action add --type whitelist \
  --ip 192.168.1.100 --port 22 --protocol tcp --ingress

# 阻止特定 IP 的入站流量
sudo ./bin/bgo firewall-update --action add --type blacklist \
  --ip 10.0.0.50 --ingress

# 查看入站规则
sudo ./bin/bgo firewall-update --action list --ingress

# 查看入站统计
sudo ./bin/bgo firewall-update --action stats --ingress
```

#### Egress（出站流量）规则

```bash
# 阻止访问特定外部 DNS 服务器
sudo ./bin/bgo firewall-update --action add --type blacklist \
  --ip 8.8.8.8 --port 53 --protocol udp --egress

# 允许访问特定网段
sudo ./bin/bgo firewall-update --action add --type whitelist \
  --ip 172.16.0.0/16 --egress

# 查看出站规则
sudo ./bin/bgo firewall-update --action list --egress

# 查看出站统计
sudo ./bin/bgo firewall-update --action stats --egress
```

### 支持的协议

- `tcp` - TCP 协议
- `udp` - UDP 协议
- `icmp` - ICMP 协议（ping）
- `any` - 所有协议（默认）

### IP 地址格式

支持两种格式：
- **单个 IP**：`192.168.1.100`
- **CIDR 子网**：`192.168.1.0/24`、`10.0.0.0/8`

---

## firewall-ratelimit - 流量限制管理

### 基本概念

流量限制使用**令牌桶算法**，可以限制：
- **PPS（Packets Per Second）**：每秒数据包数量
- **BPS（Bytes Per Second）**：每秒字节数（带宽）

流量限制在防火墙规则**之后**执行。

### 常用命令

#### 1. 查看当前配置

```bash
sudo ./bin/bgo firewall-ratelimit --show-config
```

输出示例：
```
Rate Limit Configuration:
  Status:           Enabled
  Packets/sec:      1000 pps (1.00 Kpps)
  Bytes/sec:        1048576 bytes (1.00 MB/s)
```

#### 2. 启用流量限制

```bash
# 同时限制 PPS 和 BPS
sudo ./bin/bgo firewall-ratelimit --enable --pps 1000 --bps 1048576

# 只限制数据包速率（1万包/秒）
sudo ./bin/bgo firewall-ratelimit --enable --pps 10000

# 只限制带宽（10 MB/秒）
sudo ./bin/bgo firewall-ratelimit --enable --bps 10485760
```

#### 3. 查看统计信息

```bash
sudo ./bin/bgo firewall-ratelimit --show-stats
```

输出示例：
```
Rate Limit Statistics:
  Passed Packets:   45623
  Passed Bytes:     12845632 (12.25 MB)
  Dropped Packets:  1234
  Dropped Bytes:    345678 (0.33 MB)
  Drop Rate:        2.63%
```

#### 4. 重置统计信息

```bash
sudo ./bin/bgo firewall-ratelimit --reset-stats
```

#### 5. 禁用流量限制

```bash
sudo ./bin/bgo firewall-ratelimit --disable
```

### 常见限制值参考

#### PPS（包/秒）限制

| 限制值 | 说明 | 场景 |
|--------|------|------|
| 1000 | 1K pps | 低速连接 |
| 5000 | 5K pps | 普通服务器 |
| 10000 | 10K pps | 中型服务器 |
| 100000 | 100K pps | 高性能服务器 |

#### BPS（字节/秒）限制

| 限制值 | 换算 | 说明 |
|--------|------|------|
| 1048576 | 1 MB/s | 8 Mbps |
| 10485760 | 10 MB/s | 80 Mbps |
| 52428800 | 50 MB/s | 400 Mbps |
| 104857600 | 100 MB/s | 800 Mbps |
| 1073741824 | 1 GB/s | 8 Gbps |

### 实时监控

使用 `watch` 命令实时查看统计：

```bash
# 每秒刷新一次统计信息
watch -n 1 'sudo ./bin/bgo firewall-ratelimit --show-stats'
```

---

## 完整使用示例

### 场景 1：保护 SSH 服务

```bash
# 1. 启动防火墙
sudo ./bin/bgo firewall-server start --interface eth0

# 2. 只允许公司网段访问 SSH
sudo ./bin/bgo firewall-update --xdp --type whitelist --action add \
  --ip 192.168.1.0/24 --port 22 --protocol tcp

# 3. 限制连接速率防止暴力破解
sudo ./bin/bgo firewall-ratelimit --enable --pps 1000

# 4. 查看防火墙效果
sudo ./bin/bgo firewall-update --xdp --action stats
sudo ./bin/bgo firewall-ratelimit --show-stats
```

### 场景 2：阻止恶意 IP

```bash
# 添加黑名单阻止攻击者
sudo ./bin/bgo firewall-update --xdp --type blacklist --action add \
  --ip 203.0.113.0/24

sudo ./bin/bgo firewall-update --xdp --type blacklist --action add \
  --ip 198.51.100.50

# 查看被阻止的统计
sudo ./bin/bgo firewall-update --xdp --action stats
```

### 场景 3：限制出站流量

```bash
# 阻止访问特定外部服务
sudo ./bin/bgo firewall-update --action add --type blacklist \
  --ip 8.8.8.8 --port 53 --protocol udp --egress

# 查看出站流量统计
sudo ./bin/bgo firewall-update --action stats --egress
```

### 场景 4：DDoS 防护

```bash
# 1. 启用严格的流量限制
sudo ./bin/bgo firewall-ratelimit --enable --pps 5000 --bps 52428800

# 2. 添加已知攻击者到黑名单
sudo ./bin/bgo firewall-update --xdp --type blacklist --action add \
  --ip 10.0.0.0/8

# 3. 实时监控
watch -n 1 'sudo ./bin/bgo firewall-ratelimit --show-stats'
```

---

## 多网卡支持

如果需要管理多个网卡，使用不同的 `--pin-path`：

```bash
# 网卡 1：eth0
sudo ./bin/bgo firewall-server start --interface eth0 \
  --pin-path /sys/fs/bpf/firewall_eth0 --listen :8080 &

# 网卡 2：eth1
sudo ./bin/bgo firewall-server start --interface eth1 \
  --pin-path /sys/fs/bpf/firewall_eth1 --listen :8081 &

# 配置 eth0 规则
sudo ./bin/bgo firewall-update --pin-path /sys/fs/bpf/firewall_eth0 \
  --xdp --type whitelist --action add --ip 192.168.1.0/24

# 配置 eth1 规则
sudo ./bin/bgo firewall-update --pin-path /sys/fs/bpf/firewall_eth1 \
  --xdp --type whitelist --action add --ip 10.0.0.0/8

# 配置 eth0 流量限制
sudo ./bin/bgo firewall-ratelimit --pin-path /sys/fs/bpf/firewall_eth0 \
  --enable --pps 10000 --bps 10485760

# 配置 eth1 流量限制
sudo ./bin/bgo firewall-ratelimit --pin-path /sys/fs/bpf/firewall_eth1 \
  --enable --pps 5000 --bps 5242880
```

---

## 命令参数速查

### firewall-update

```bash
--xdp              # 使用 XDP 模式（推荐）
--ingress          # TC 入站流量模式
--egress           # TC 出站流量模式
--type string      # 规则类型：whitelist 或 blacklist（默认：whitelist）
--action string    # 操作：add、remove、list、stats（默认：list）
--ip string        # IP 地址或 CIDR 范围
--port uint16      # 端口号（0 表示所有端口）
--protocol string  # 协议：tcp、udp、icmp、any（默认：any）
--index uint32     # 删除规则时的索引号
--pin-path string  # BPF 文件系统 pin 路径（默认：/sys/fs/bpf/firewall）
```

### firewall-ratelimit

```bash
--enable           # 启用流量限制
--disable          # 禁用流量限制
--pps uint64       # 每秒数据包限制（0 表示无限制）
--bps uint64       # 每秒字节数限制（0 表示无限制）
--show-config      # 显示当前配置
--show-stats       # 显示统计信息
--reset-stats      # 重置统计信息
--pin-path string  # BPF 文件系统 pin 路径（默认：/sys/fs/bpf/firewall）
```

---

## 常见问题

### Q1: 规则不生效？

确保 firewall-server 正在运行：
```bash
ps aux | grep firewall-server
```

### Q2: 如何清空所有规则？

逐个删除规则，或者重启 firewall-server：
```bash
# 停止服务器（Ctrl+C）
# 清理 BPF 资源
sudo ./bin/bgo firewall-server cleanup-maps
# 重新启动
sudo ./bin/bgo firewall-server start --interface eth0
```

### Q3: 流量限制太严格导致正常流量被丢弃？

调大限制值或禁用：
```bash
# 调大限制
sudo ./bin/bgo firewall-ratelimit --enable --pps 20000 --bps 104857600

# 或者禁用
sudo ./bin/bgo firewall-ratelimit --disable
```

### Q4: 如何测试规则是否生效？

使用 `stats` 命令查看统计信息：
```bash
# 查看防火墙统计
sudo ./bin/bgo firewall-update --xdp --action stats

# 查看流量限制统计
sudo ./bin/bgo firewall-ratelimit --show-stats
```

---

## 进阶技巧

### 1. 组合使用白名单和黑名单

```bash
# 默认允许所有流量，只阻止特定 IP
sudo ./bin/bgo firewall-update --xdp --type blacklist --action add \
  --ip 10.0.0.50

# 或者：默认拒绝所有流量，只允许特定 IP
sudo ./bin/bgo firewall-update --xdp --type whitelist --action add \
  --ip 192.168.1.0/24
```

### 2. 脚本化管理

创建规则管理脚本：
```bash
#!/bin/bash
# add_rules.sh

# 允许的 IP 列表
ALLOWED_IPS=(
  "192.168.1.0/24"
  "10.0.0.0/16"
  "172.16.0.100"
)

for IP in "${ALLOWED_IPS[@]}"; do
  sudo ./bin/bgo firewall-update --xdp --type whitelist --action add --ip "$IP"
done

echo "规则添加完成！"
```

### 3. 日志和监控

实时查看统计变化：
```bash
# 终端 1：监控防火墙
watch -n 1 'sudo ./bin/bgo firewall-update --xdp --action stats'

# 终端 2：监控流量限制
watch -n 1 'sudo ./bin/bgo firewall-ratelimit --show-stats'
```

---

## 相关文档

- **详细功能说明**：`docs/RATELIMIT.md`
- **快速入门**：`docs/RATELIMIT_QUICKSTART.md`
- **IP 范围支持**：`docs/IP_RANGE_SUPPORT.md`
- **架构说明**：`docs/RATELIMIT_PIN_MANAGEMENT.md`
- **LVS NAT 配置**：`bpf/firewall/LVS_NAT_GUIDE.md`

---

## 总结

- **firewall-update**：管理防火墙规则（白名单/黑名单）
- **firewall-ratelimit**：管理流量限制（PPS/BPS）
- 两个命令都需要 **firewall-server** 先启动
- 支持 **XDP 和 TC** 两种模式
- 支持 **单 IP 和 CIDR 网段**
- 实时生效，无需重启服务

开始使用防火墙保护你的服务器吧！🔥🛡️
