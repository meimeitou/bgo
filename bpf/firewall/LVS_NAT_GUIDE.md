# LVS NAT Mode with XDP Firewall

这个项目在原有的 XDP 防火墙基础上增加了 LVS NAT 模式的负载均衡功能。

## 功能特性

1. **防火墙功能**：基于 XDP 的高性能包过滤
2. **LVS NAT 模式**：支持目的地址转换的负载均衡
3. **连接跟踪**：处理双向流量的地址转换
4. **独立管理**：专门的 `firewall-lvs` 命令管理 LVS 配置

## 工作流程

```
客户端 ──┬──> 防火墙过滤 ──┬──> LVS DNAT ──> 后端服务器
        │               │
        │               └──> 直接通过
        └──> 被防火墙阻断

后端服务器 ──> LVS SNAT ──> 客户端
```

## 编译和部署

1. **编译项目**：
```bash
make
```

2. **加载 XDP 程序**：
```bash
sudo ./bin/bgo firewall-server start --interface enp0s3 
```

3. **启用 LVS 功能**：
```bash
sudo ./bin/bgo firewall-lvs enable
```

## LVS 配置管理

### 1. 添加 DNAT 规则

将访问 VIP:80 的流量转发到后端服务器：

```bash
# 添加 TCP 转发规则
sudo ./bin/bgo firewall-lvs add-dnat \
  --vip 192.168.1.100 \
  --vport 80 \
  --rip 192.168.1.10 \
  --rport 8080 \
  --protocol tcp

# 添加多个后端服务器
sudo ./bin/bgo firewall-lvs add-dnat \
  --vip 192.168.1.100 \
  --vport 80 \
  --rip 192.168.1.11 \
  --rport 8080 \
  --protocol tcp

# 添加 UDP 转发规则
sudo ./bin/bgo firewall-lvs add-dnat \
  --vip 192.168.1.100 \
  --vport 53 \
  --rip 192.168.1.12 \
  --rport 53 \
  --protocol udp
```

### 2. 查看 DNAT 规则

```bash
sudo ./bin/bgo firewall-lvs list-dnat
```

输出示例：
```
LVS DNAT Rules:
Index VIP             VPort  Protocol RIP             RPort  Enabled
----- --------------- ------  -------- --------------- ------  --------
0     192.168.1.100   80     tcp      192.168.1.10    8080   true
1     192.168.1.100   80     tcp      192.168.1.11    8080   true
2     192.168.1.100   53     udp      192.168.1.12    53     true

Total rules: 3
```

### 3. 删除 DNAT 规则

```bash
sudo ./bin/bgo firewall-lvs remove-dnat \
  --vip 192.168.1.100 \
  --vport 80 \
  --protocol tcp
```

### 4. 查看 LVS 状态

```bash
sudo ./bin/bgo firewall-lvs status
```

输出示例：
```
LVS Status: ENABLED

Active Connections:
Client IP       Port   Original VIP    Port   Target IP       Port
--------------- ------ --------------- ------ --------------- ------
192.168.1.200   12345  192.168.1.100   80     192.168.1.10    8080
192.168.1.201   12346  192.168.1.100   80     192.168.1.11    8080

Total active connections: 2
```

### 5. 启用/禁用 LVS

```bash
# 启用 LVS
sudo ./bin/bgo firewall-lvs enable

# 禁用 LVS
sudo ./bin/bgo firewall-lvs disable
```

### 6. 清理连接跟踪

```bash
sudo ./bin/bgo firewall-lvs cleanup
```

## 测试示例

### 1. 设置测试环境

```bash
# 1. 启动后端 Web 服务器（在 192.168.1.10:8080）
python3 -m http.server 8080

# 2. 配置 VIP（在 LVS 服务器上）
sudo ip addr add 192.168.1.100/24 dev eth0

# 3. 添加 DNAT 规则
sudo ./bin/bgo firewall-lvs add-dnat \
  --vip 192.168.1.100 \
  --vport 80 \
  --rip 192.168.1.10 \
  --rport 8080 \
  --protocol tcp
```

### 2. 测试负载均衡

```bash
# 从客户端访问 VIP
curl http://192.168.1.100/

# 查看连接状态
sudo ./bin/bgo firewall-lvs status
```

## 配置文件

### BPF Maps 位置

**XDP 防火墙和 LVS Maps：**
- `/sys/fs/bpf/firewall/whitelist_map`: XDP 白名单规则
- `/sys/fs/bpf/firewall/blacklist_map`: XDP 黑名单规则  
- `/sys/fs/bpf/firewall/stats_map`: XDP 统计信息
- `/sys/fs/bpf/firewall/config_map`: 配置参数
- `/sys/fs/bpf/firewall/lvs_dnat_map`: DNAT 规则映射表
- `/sys/fs/bpf/firewall/conn_track_map`: 连接跟踪表
- `/sys/fs/bpf/firewall/backend_map`: 后端服务器配置
- `/sys/fs/bpf/firewall/service_map`: 服务配置

**TC 防火墙 Maps：**
- `/sys/fs/bpf/firewall/tc_ingress_whitelist`: TC 入站白名单规则
- `/sys/fs/bpf/firewall/tc_ingress_blacklist`: TC 入站黑名单规则
- `/sys/fs/bpf/firewall/tc_egress_whitelist`: TC 出站白名单规则
- `/sys/fs/bpf/firewall/tc_egress_blacklist`: TC 出站黑名单规则
- `/sys/fs/bpf/firewall/tc_stats_map`: TC 统计信息

### Map 兼容性问题

如果遇到 map 规格不兼容的错误（如 "MaxEntries changed"），可以使用以下命令清理所有 pinned maps：

```bash
# 强制清理所有 BPF maps（包括 XDP、LVS 和 TC 相关的 maps）
sudo ./bin/bgo firewall-server cleanup-maps --force

# 重新启动防火墙服务重建 maps
sudo ./bin/bgo firewall-server start --interface enp0s3
```

### 防火墙规则配置

LVS 处理在防火墙过滤之后，可以结合使用：

```bash
# 配置防火墙规则
sudo ./bin/bgo firewall update --add-whitelist \
  --ip-start 192.168.1.0 \
  --ip-end 192.168.1.255 \
  --port 80 \
  --protocol tcp

# 然后配置 LVS 转发
sudo ./bin/bgo firewall-lvs add-dnat \
  --vip 192.168.1.100 \
  --vport 80 \
  --rip 192.168.1.10 \
  --rport 8080 \
  --protocol tcp
```

## 性能特性

1. **零拷贝处理**：XDP 在驱动层处理数据包
2. **连接跟踪**：使用 LRU Hash 表自动清理旧连接
3. **校验和更新**：增量更新 IP/TCP/UDP 校验和
4. **防火墙集成**：防火墙过滤在 LVS 处理之前执行

## 故障排查

### 1. Map 兼容性问题

**问题**: 出现类似 "map spec is incompatible with existing map" 错误
```
failed to initialize maps: failed to load and assign new objects: field TcEgressFilter: program tc_egress_filter: map tc_ingress_whitelist: use pinned map tc_ingress_whitelist: MaxEntries: 10 changed to 100: map spec is incompatible with existing map
```

**解决方案**:
```bash
# 1. 强制清理所有 BPF maps
sudo ./bin/bgo firewall-server cleanup-maps --force

# 2. 重新启动防火墙服务
sudo ./bin/bgo firewall-server start --interface enp0s3
```

### 2. 检查 XDP 程序加载状态

```bash
sudo ip link show enp0s3
```

### 3. 检查 TC 程序状态

```bash
# 查看 TC qdisc
sudo tc qdisc show dev enp0s3

# 查看 TC 过滤器
sudo tc filter show dev enp0s3 ingress
sudo tc filter show dev enp0s3 egress
```

### 4. 检查 BPF Maps

```bash
sudo bpftool map list | grep firewall
sudo ls -la /sys/fs/bpf/firewall/
```

### 5. 查看日志

```bash
sudo dmesg | grep -i xdp
sudo dmesg | grep -i bpf
sudo journalctl -f
```

### 6. 网络配置检查

```bash
# 检查路由
ip route show

# 检查 ARP 表
arp -a

# 检查防火墙规则
sudo iptables -L -n
```

## 限制说明

1. **最大规则数**：支持最多 100 条 DNAT 规则
2. **连接跟踪**：支持最多 10,000 个并发连接
3. **协议支持**：当前支持 TCP 和 UDP
4. **地址要求**：VIP 需要配置在 LVS 服务器网卡上

## 与传统 LVS 对比

| 特性 | 传统 LVS | XDP LVS |
|------|----------|---------|
| 处理位置 | 内核网络栈 | XDP (驱动层) |
| 性能 | 高 | 极高 |
| CPU 使用 | 中等 | 很低 |
| 延迟 | 低 | 极低 |
| 防火墙集成 | 需要额外配置 | 原生集成 |
| 配置复杂度 | 中等 | 简单 |
