# BGO Test Environment Setup Guide

这个脚本用于创建和管理 BGO XDP/TC 防火墙和 LVS 的测试环境，基于 xdp-tutorial 的 testenv.sh 脚本。

## 功能特性

- **网络命名空间隔离**：创建独立的网络测试环境
- **XDP/TC 防火墙集成**：自动设置 BGO 防火墙
- **LVS 负载均衡支持**：可选的 LVS 功能测试
- **IPv4/IPv6 双栈支持**：支持传统 IPv4 和现代 IPv6
- **VLAN 支持**：可选的 VLAN 配置
- **API 测试**：内置 BGO API 测试功能

## 安装和准备

### 1. 构建项目

```bash
cd /home/vagrant/bgo
make
```

### 2. 检查依赖

脚本需要以下工具：
- `ethtool`
- `ip`
- `tc`
- `ping`
- `curl`
- `bpftool`

```bash
# 在 Ubuntu/Debian 上安装依赖
sudo apt-get update
sudo apt-get install iproute2 ethtool tcpdump curl

# 检查 bpftool
which bpftool || echo "请安装 bpftool"
```

## 基本使用

### 1. 创建测试环境

```bash
# 创建基本测试环境
sudo ./scripts/testenv.sh setup

# 创建带 IPv4 支持的环境
sudo ./scripts/testenv.sh --legacy-ip setup

# 创建带 LVS 支持的环境
sudo ./scripts/testenv.sh --lvs setup

# 创建带 VLAN 支持的环境
sudo ./scripts/testenv.sh --vlan setup
```

### 2. 查看环境状态

```bash
sudo ./scripts/testenv.sh status
```

输出示例：
```
Currently selected environment: bgo-test-1a2b
  Namespace:      bgo-test-1a2b
  Prefix:         fc00:dead:cafe:1a2b::/64
  Legacy prefix:  10.11.26.0/24
  Interface:      bgo-test-1a2b UP 10.11.26.1/24 fc00:dead:cafe:1a2b::1/64
  BGO Firewall:   Running (PID: 12345, API: http://localhost:8080)

All existing environments:
  bgo-test-1a2b
  bgo-test-2c3d
```

### 3. 进入测试环境

```bash
# 在命名空间中执行 shell
sudo ./scripts/testenv.sh enter

# 在命名空间中执行单个命令
sudo ./scripts/testenv.sh exec ip addr show

# 在命名空间中执行 ping 测试（参数正确传递）
sudo ./scripts/testenv.sh ping -c 3
```

### 4. 网络测试

```bash
# 运行 ping 测试
sudo ./scripts/testenv.sh ping -c 5

# IPv4 ping 测试
sudo ./scripts/testenv.sh --legacy-ip ping -c 3

# 抓包分析
sudo ./scripts/testenv.sh tcpdump -c 10 icmp

# 在内部接口抓包
sudo ./scripts/testenv.sh --inner tcpdump -i veth0 -c 5
```

### 5. 防火墙和 API 测试

```bash
# 测试 BGO API 连接
sudo ./scripts/testenv.sh curl

# 查看防火墙统计
sudo ./scripts/testenv.sh bgo firewall-update --action stats

# 添加防火墙规则
sudo ./scripts/testenv.sh bgo firewall-update \
  --action add --type whitelist \
  --ip 10.11.0.0/16 --port 80 --protocol tcp

# 查看防火墙规则
sudo ./scripts/testenv.sh bgo firewall-update --action list

# 使用 API 添加规则
sudo ./scripts/testenv.sh curl -X POST http://localhost:8080/api/rules/whitelist \
  -H "Content-Type: application/json" \
  -d '{"ip_range":"10.11.0.0/16","port":22,"protocol":"tcp"}'

# 查看 API 状态
sudo ./scripts/testenv.sh curl http://localhost:8080/api/status
```

### 6. LVS 测试

```bash
# 启用 LVS 功能
sudo ./scripts/testenv.sh bgo firewall-lvs enable

# 添加 DNAT 规则
sudo ./scripts/testenv.sh bgo firewall-lvs add-dnat \
  --vip 10.11.2.1 \
  --vport 80 \
  --rip 10.217.56.222 \
  --rport 9090 \
  --protocol tcp

# 查看 LVS 状态
sudo ./scripts/testenv.sh bgo firewall-lvs status

# 查看 DNAT 规则
sudo ./scripts/testenv.sh bgo firewall-lvs list-dnat
```

### 7. 清理环境

```bash
# 停止并删除当前环境
sudo ./scripts/testenv.sh teardown

# 重置环境（先删除再重建）
sudo ./scripts/testenv.sh reset
```

## 高级使用

### 1. 多环境管理

```bash
# 创建命名环境
sudo ./scripts/testenv.sh --name test-env-1 setup
sudo ./scripts/testenv.sh --name test-env-2 setup

# 切换环境
sudo ./scripts/testenv.sh --name test-env-1 status
sudo ./scripts/testenv.sh --name test-env-2 ping

# 强制创建新环境（即使当前环境存在）
sudo ./scripts/testenv.sh --gen-new setup
```

### 2. 配置自定义

通过环境变量自定义配置：

```bash
# 自定义网络前缀
export BGO_TEST_IP4_SUBNET="172.16.1"
export BGO_TEST_IP6_SUBNET="fd00:test:cafe"

# 自定义 API 端口
export BGO_TEST_API_PORT="9090"

# 自定义状态目录
export BGO_TEST_STATEDIR="/tmp/my-bgo-test"

# 然后运行脚本
sudo -E ./scripts/testenv.sh setup
```

### 3. 创建 Shell 别名

```bash
# 生成别名
eval $(sudo ./scripts/testenv.sh alias)

# 现在可以使用 bgo-test 命令
bgo-test setup
bgo-test status
bgo-test enter
```

## 实际测试场景

### 场景 1：基本防火墙测试

```bash
# 1. 创建测试环境
sudo ./scripts/testenv.sh --legacy-ip setup

# 2. 测试连通性
sudo ./scripts/testenv.sh ping -c 3

# 3. 添加黑名单规则阻止外部 IP
sudo ./scripts/testenv.sh bgo firewall-update \
  --action add --type blacklist \
  --ip 8.8.8.8 --protocol icmp

# 4. 在命名空间中测试被阻止的流量
sudo ./scripts/testenv.sh exec ping -c 3 8.8.8.8

# 5. 查看统计信息
sudo ./scripts/testenv.sh bgo firewall-update --action stats
```

### 场景 2：LVS 负载均衡测试

**重要提示**：LVS 是为处理从外部到内部的流量设计的，需要正确配置网络拓扑。

```bash
# 1. 创建 LVS 测试环境
sudo ./scripts/testenv.sh --legacy-ip --lvs setup

# 2. 在命名空间中启动后端服务
sudo ./scripts/testenv.sh exec python3 -m http.server 9090 &
sleep 2  # 等待服务启动

# 3. 验证后端服务正常运行
sudo ./scripts/testenv.sh exec ss -tlnp | grep 9090
sudo ./scripts/testenv.sh exec curl http://10.11.2.2:9090/  # 直接测试

# 4. 配置 LVS DNAT 规则（使用不冲突的 VIP）
sudo ./scripts/testenv.sh bgo firewall-lvs add-dnat \
  --vip 192.168.100.10 \
  --vport 80 \
  --rip 10.11.2.2 \
  --rport 9090 \
  --protocol tcp

# 5. 配置网络让外部可以访问 VIP
# 方法1：添加 VIP 别名到外部接口
sudo ip addr add 192.168.100.10/32 dev $(sudo ./scripts/testenv.sh status | grep Interface | awk '{print $2}')

# 方法2：或者添加路由（如果使用真实的外部客户端）
# sudo ip route add 192.168.100.10/32 dev $(sudo ./scripts/testenv.sh status | grep Interface | awk '{print $2}')

# 6. 查看 DNAT 规则
sudo ./scripts/testenv.sh bgo firewall-lvs list-dnat

# 7. 测试负载均衡（从外部访问）
# 注意：由于网络拓扑限制，在测试环境中需要特殊配置
echo "Testing LVS forwarding..."
curl -m 5 http://192.168.100.10:80/ || echo "LVS forwarding may need additional network configuration"

# 8. 查看连接状态和统计
sudo ./scripts/testenv.sh bgo firewall-lvs status
sudo ./scripts/testenv.sh bgo firewall-update --action stats --xdp
```

**LVS 测试常见问题**：
- **VIP 冲突**：不要使用与现有接口相同的 IP（如 10.11.2.1）
- **路由问题**：确保外部客户端流量能正确路由到 XDP 程序所在的接口
- **ARP 响应**：VIP 需要在外部接口上配置或使用代理 ARP
- **流量方向**：LVS 处理的是入站流量，从命名空间内发起的连接不会触发 LVS

### 场景 3：性能测试

```bash
# 1. 创建测试环境
sudo ./scripts/testenv.sh --legacy-ip setup

# 2. 启动抓包
sudo ./scripts/testenv.sh tcpdump -w /tmp/bgo-test.pcap &

# 3. 生成测试流量
sudo ./scripts/testenv.sh exec ping -f -c 10000 $(ip route get 8.8.8.8 | awk '{print $3}')

# 4. 查看性能统计
sudo ./scripts/testenv.sh bgo firewall-update --action stats

# 5. 分析抓包结果
tcpdump -r /tmp/bgo-test.pcap | head -20
```

## 故障排查

### 1. 环境创建失败

```bash
# 检查权限
whoami  # 应该是 root 或使用 sudo

# 检查依赖
./scripts/testenv.sh --help

# 查看详细错误
sudo ./scripts/testenv.sh setup 2>&1 | tee setup.log
```

### 2. BGO 防火墙启动失败

```bash
# 检查 BGO 二进制文件
ls -la bin/bgo

# 重新构建项目
make clean && make

# 查看防火墙日志
sudo ./scripts/testenv.sh status
cat /tmp/bgo-firewall-*.log
```

### 3. 网络连接问题

```bash
# 检查网络接口
sudo ./scripts/testenv.sh exec ip addr show

# 检查路由
sudo ./scripts/testenv.sh exec ip route show

# 检查 XDP 程序
sudo ./scripts/testenv.sh exec ip link show

# 检查 TC 程序
sudo tc qdisc show
sudo tc filter show dev $(sudo ./scripts/testenv.sh status | grep Interface | awk '{print $2}') ingress
```

### 4. BPF Map 问题

```bash
# 查看 BPF Maps
sudo bpftool map list | grep firewall

# 强制清理 Maps
sudo ./scripts/testenv.sh bgo firewall-server cleanup-maps --force

# 重新启动环境
sudo ./scripts/testenv.sh reset
```

### 5. XDP 防火墙规则不生效问题

这是一个常见且重要的问题。如果你发现防火墙规则已添加但流量仍然通过：

#### 问题诊断步骤

```bash
# 1. 检查规则是否正确添加
sudo ./scripts/testenv.sh bgo firewall-update --action list

# 2. 检查统计数据
sudo ./scripts/testenv.sh bgo firewall-update --action stats --xdp

# 3. 检查 XDP 程序是否正确加载
sudo bpftool net list

# 4. 测试流量并观察统计变化
sudo ./scripts/testenv.sh exec ping -c 3 -4 目标IP
```

#### 完整的测试和验证流程

```bash
# 1. 创建测试环境
sudo ./scripts/testenv.sh --legacy-ip setup

# 2. 清除可能冲突的白名单ICMP规则
sudo ./scripts/testenv.sh bgo firewall-update --action list
sudo ./scripts/testenv.sh bgo firewall-update \
  --action remove --type whitelist --index 1  # 如果存在ICMP白名单

# 3. 添加正确的黑名单规则（阻止源IP）
sudo ./scripts/testenv.sh bgo firewall-update \
  --action add --type blacklist --ip 10.11.2.2 --protocol icmp

# 4. 测试（应该被阻止）
sudo ./scripts/testenv.sh exec ping -c 3 -4 10.11.2.1

# 5. 验证统计数据
sudo ./scripts/testenv.sh bgo firewall-update --action stats --xdp
```

#### 调试技巧

```bash
# 查看BPF程序加载情况
sudo bpftool prog list | grep xdp

# 查看BPF Maps内容
sudo bpftool map dump name blacklist_map
sudo bpftool map dump name whitelist_map

# 实时监控统计数据
watch "sudo ./scripts/testenv.sh bgo firewall-update --action stats --xdp"
```

### 6. LVS DNAT 规则不生效问题

LVS 负载均衡配置比较复杂，常见问题和解决方案：

#### 问题诊断步骤

```bash
# 1. 检查 LVS 是否启用
sudo ./scripts/testenv.sh bgo firewall-lvs status

# 2. 检查 DNAT 规则
sudo ./scripts/testenv.sh bgo firewall-lvs list-dnat

# 3. 检查后端服务是否运行
sudo ./scripts/testenv.sh exec ss -tlnp | grep <后端端口>

# 4. 检查网络连通性
ping <VIP>  # 从外部测试
sudo ./scripts/testenv.sh exec curl http://<RIP>:<RPort>/  # 直接测试后端
```

#### 常见问题和解决方案

**问题 1：VIP 地址冲突**
- **现象**：`curl: (7) Failed to connect to <VIP> port 80: Connection refused`
- **原因**：VIP 与现有接口地址相同（如使用 10.11.2.1）
- **解决**：使用不同的 VIP 地址

```bash
# 错误：使用现有接口地址作为 VIP
sudo ./scripts/testenv.sh bgo firewall-lvs add-dnat --vip 10.11.2.1 --vport 80 ...

# 正确：使用独立的 VIP 地址
sudo ./scripts/testenv.sh bgo firewall-lvs add-dnat --vip 192.168.100.10 --vport 80 ...
```

**问题 2：网络路由和 ARP 问题**
- **现象**：`No route to host` 或 `Destination Host Unreachable`
- **原因**：外部无法正确路由到 VIP 或 ARP 解析失败

```bash
# 解决方案1：在外部接口添加 VIP 别名
INTERFACE=$(sudo ./scripts/testenv.sh status | grep Interface | awk '{print $2}')
sudo ip addr add 192.168.100.10/32 dev $INTERFACE

# 解决方案2：添加路由
sudo ip route add 192.168.100.10/32 dev $INTERFACE

# 验证路由
ip route get 192.168.100.10
ping -c 1 192.168.100.10
```

**问题 3：流量方向错误**
- **问题**：从命名空间内访问 VIP 不会触发 LVS
- **原因**：LVS 处理的是入站流量，XDP 程序在外部接口上
- **解决**：从外部（宿主机）访问 VIP

```bash
# 错误：从命名空间内访问（不会触发 LVS）
sudo ./scripts/testenv.sh exec curl http://192.168.100.10:80/

# 正确：从外部访问（会触发 LVS）
curl http://192.168.100.10:80/
```

**问题 4：后端服务不可达**
- **检查 RIP地址是否正确**
- **检查后端服务是否监听正确的端口**
- **检查防火墙规则是否阻止了转发**

```bash
# 验证后端服务
sudo ./scripts/testenv.sh exec curl http://10.11.2.2:9090/

# 检查是否有白名单/黑名单规则冲突
sudo ./scripts/testenv.sh bgo firewall-update --action list
```

#### 完整的 LVS 测试流程

```bash
# 1. 创建环境并启动后端服务
sudo ./scripts/testenv.sh --legacy-ip --lvs setup
sudo ./scripts/testenv.sh exec python3 -m http.server 9090 &
sleep 2

# 2. 验证后端服务
sudo ./scripts/testenv.sh exec ss -tlnp | grep 9090
sudo ./scripts/testenv.sh exec curl http://10.11.2.2:9090/

# 3. 配置 LVS（使用独立的 VIP）
sudo ./scripts/testenv.sh bgo firewall-lvs add-dnat \
  --vip 192.168.100.10 --vport 80 \
  --rip 10.11.2.2 --rport 9090 --protocol tcp

# 4. 配置网络（选择其中一种方法）
INTERFACE=$(sudo ./scripts/testenv.sh status | grep Interface | awk '{print $2}')
sudo ip addr add 192.168.100.10/32 dev $INTERFACE

# 5. 验证网络连通性
ping -c 1 192.168.100.10

# 6. 测试 LVS 转发
curl -m 5 http://192.168.100.10:80/

# 7. 查看状态和统计
sudo ./scripts/testenv.sh bgo firewall-lvs status
sudo ./scripts/testenv.sh bgo firewall-update --action stats --xdp
```
