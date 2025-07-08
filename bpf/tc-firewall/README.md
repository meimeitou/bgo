# TC Firewall 使用说明

## 简介

这个TC防火墙使用eBPF技术在内核级别过滤网络包，支持基于IP地址和端口的入站/出站流量控制。

## 功能特性

- **高性能**: 在内核空间处理，避免用户空间切换开销
- **双向过滤**: 支持ingress和egress流量过滤
- **灵活规则**: 支持IP黑名单、端口黑名单和IP白名单
- **实时统计**: 提供详细的流量统计信息
- **零拷贝**: 直接在内核中决定包的命运，无需拷贝到用户空间

## 安装要求

- Linux内核 >= 4.15 (支持TC eBPF)
- Root权限
- clang编译器
- libbpf库

## 使用方法

### 1. 基本使用

```bash
# 在eth0接口上启动防火墙
sudo ./bgo tc-firewall --interface eth0
```

### 2. 阻止特定IP

```bash
# 阻止来自/发往特定IP的流量
sudo ./bgo tc-firewall --interface eth0 --blocked-ips 192.168.1.100,10.0.0.50
```

### 3. 阻止特定端口

```bash
# 阻止SSH、HTTP和HTTPS端口
sudo ./bgo tc-firewall --interface eth0 --blocked-ports 22,80,443
```

### 4. 白名单模式

```bash
# 只允许特定IP访问
sudo ./bgo tc-firewall --interface eth0 --allowed-ips 192.168.1.1,192.168.1.2
```

### 5. 混合模式

```bash
# 允许内网访问，但阻止特定IP和端口
sudo ./bgo tc-firewall --interface eth0 \
  --allowed-ips 192.168.1.0/24 \
  --blocked-ips 192.168.1.100 \
  --blocked-ports 22,23
```

## 规则优先级

1. **白名单优先**: 如果IP在白名单中，直接允许
2. **IP黑名单**: 检查源IP和目标IP是否被阻止
3. **端口黑名单**: 检查源端口和目标端口是否被阻止
4. **默认允许**: 如果没有匹配到任何规则，默认允许

## 统计信息

程序会每5秒打印一次统计信息：

```
=== TC Firewall Statistics ===
Total Packets:    1524
Dropped Packets:  45
Accepted Packets: 1479
TCP Packets:      1200
UDP Packets:      280
ICMP Packets:     44
Other Packets:    0
Drop Rate:        2.95%
===============================
```

## 日志信息

被阻止的包会在内核日志中记录：

```bash
# 查看内核日志
sudo dmesg | grep -i blocked

# 或者使用bpftrace查看实时日志
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep bgo
```

## 网络接口管理

### 查看可用接口

```bash
ip link show
```

### 创建TC qdisc (如果需要)

```bash
# 为接口添加clsact qdisc
sudo tc qdisc add dev eth0 clsact

# 查看TC规则
sudo tc filter show dev eth0 ingress
sudo tc filter show dev eth0 egress
```

### 清理TC规则

```bash
# 删除clsact qdisc（会删除所有相关的TC规则）
sudo tc qdisc del dev eth0 clsact
```

## 故障排除

### 1. 权限错误

```
Error: this program requires root privileges
```

解决：使用sudo运行程序

### 2. 接口不存在

```
Error: failed to get interface eth0: no such network interface
```

解决：检查接口名称是否正确

### 3. eBPF加载失败

```
Error: failed to load firewall: permission denied
```

解决：
- 确保内核支持eBPF
- 检查内核版本 >= 4.15
- 确保有root权限

### 4. 查看内核eBPF支持

```bash
# 检查内核配置
grep -i bpf /boot/config-$(uname -r)

# 检查eBPF文件系统
mount | grep bpf
```

## 性能优化

1. **Map大小调整**: 根据需要调整MAX_BLOCKED_IPS、MAX_BLOCKED_PORTS常量
2. **统计间隔**: 可以调整统计信息打印间隔以减少开销
3. **规则优化**: 将常用的IP放在白名单中以提高性能

## 注意事项

1. **网络中断**: 在生产环境中使用时要小心，错误的规则可能导致网络中断
2. **资源限制**: eBPF Maps有大小限制，大量规则可能需要调整
3. **内核版本**: 某些高级特性需要较新的内核版本
4. **兼容性**: 不同发行版的内核可能有细微差别

## 示例场景

### 场景1: 服务器安全加固

```bash
# 只允许管理网段访问，阻止危险端口
sudo ./bgo tc-firewall --interface eth0 \
  --allowed-ips 192.168.100.0/24 \
  --blocked-ports 23,135,139,445,1433,3389
```

### 场景2: 开发环境隔离

```bash
# 阻止访问生产环境IP
sudo ./bgo tc-firewall --interface eth0 \
  --blocked-ips 10.0.1.0/24,10.0.2.0/24
```

### 场景3: DDoS防护

```bash
# 阻止已知攻击IP
sudo ./bgo tc-firewall --interface eth0 \
  --blocked-ips 1.2.3.4,5.6.7.8,9.10.11.12
```
