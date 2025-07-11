# 统一防火墙 (XDP + TC 双模式支持)

基于eBPF技术实现的高性能防火墙，同时支持XDP和TC两种模式。XDP模式支持黑名单和白名单过滤，TC模式支持入站和出站流量控制。使用pinned BPF maps实现持久化规则管理和外部交互。

## 功能特性

1. **XDP模式**: 
   - **黑名单模式**: 限制特定IP/端口的服务请求，端口为0表示限制所有端口
   - **白名单模式**: 允许特定IP段请求端口，端口为0表示可以请求任意端口
   - **优先级**: 白名单优先于黑名单
2. **TC模式**:
   - **入站过滤**: 控制进入网络接口的流量
   - **出站过滤**: 控制离开网络接口的流量
   - **精确控制**: 支持IP地址和端口级别的过滤
3. **高性能**: 基于eBPF技术，在内核空间处理数据包，性能极高
4. **Pinned Maps**: BPF映射持久化，支持程序重启后保持规则状态
5. **REST API**: HTTP接口用于远程管理防火墙规则（同时支持XDP和TC API）
6. **CLI工具**: 命令行工具用于本地规则管理，支持 --xdp、--ingress、--egress 参数
7. **统计监控**: 实时流量统计和监控

## 新增命令

### firewall-server - 统一防火墙守护进程

启动支持XDP和TC双模式的防火墙守护进程，创建pinned maps并提供HTTP API接口：

```bash
# 在eth0接口启动统一防火墙服务器（同时支持XDP和TC）
sudo ./bin/bgo firewall-server --interface eth0

# 自定义监听地址和map存储路径
sudo ./bin/bgo firewall-server \
  --interface eth0 \
  --listen :8080 \
  --pin-path /sys/fs/bpf/firewall
```

### firewall-update - 规则管理工具

通过pinned maps管理防火墙规则：

```bash
# XDP Rules (whitelist/blacklist)
# 添加白名单规则（允许SSH）
sudo ./bin/bgo firewall-update \
  --xdp \
  --type whitelist \
  --action add \
  --ip 192.168.1.0/24 \
  --port 22 \
  --protocol tcp

# 添加黑名单规则（封禁IP）
sudo ./bin/bgo firewall-update \
  --xdp \
  --type blacklist \
  --action add \
  --ip 10.0.0.100

# 列出所有白名单规则
sudo ./bin/bgo firewall-update \
  --xdp \
  --type whitelist \
  --action list

# 删除规则（按索引）
sudo ./bin/bgo firewall-update \
  --xdp \
  --type whitelist \
  --action remove \
  --index 0

# 查看XDP统计信息
sudo ./bin/bgo firewall-update --xdp --action stats

# TC Rules (ingress/egress)
# 添加入站规则（阻止特定IP的入站流量）
sudo ./bin/bgo firewall-update \
  --action add \
  --ip 192.168.1.100 \
  --port 22 \
  --ingress

# 添加出站规则（阻止到特定IP和端口的出站流量）
sudo ./bin/bgo firewall-update \
  --action add \
  --ip 8.8.8.8 \
  --port 53 \
  --egress

# 列出入站规则
sudo ./bin/bgo firewall-update --action list --ingress

# 查看TC统计信息
sudo ./bin/bgo firewall-update --action stats --ingress
```

## REST API接口

防火墙服务器提供以下HTTP接口，同时支持XDP和TC两种模式：

### XDP API - 白名单管理
```bash
# 添加白名单规则
curl -X POST http://localhost:8080/api/rules/whitelist \
  -H "Content-Type: application/json" \
  -d '{"ip_range":"192.168.1.0/24","port":22,"protocol":"tcp"}'

# 获取白名单规则
curl http://localhost:8080/api/rules/whitelist

# 删除白名单规则
curl -X DELETE "http://localhost:8080/api/rules/whitelist?index=0"
```

### XDP API - 黑名单管理
```bash
# 添加黑名单规则
curl -X POST http://localhost:8080/api/rules/blacklist \
  -H "Content-Type: application/json" \
  -d '{"ip_range":"10.0.0.100","port":0,"protocol":"any"}'

# 获取黑名单规则
curl http://localhost:8080/api/rules/blacklist

# 删除黑名单规则
curl -X DELETE "http://localhost:8080/api/rules/blacklist?index=0"
```

### TC API - 入站规则管理
```bash
# 添加入站拒绝规则
curl -X POST http://localhost:8080/api/tc/rules/ingress \
  -H "Content-Type: application/json" \
  -d '{"ip_range":"192.168.1.100","port":22,"action":"deny"}'

# 获取入站规则
curl http://localhost:8080/api/tc/rules/ingress

# 删除入站规则
curl -X DELETE "http://localhost:8080/api/tc/rules/ingress?index=0"
```

### TC API - 出站规则管理
```bash
# 添加出站拒绝规则
curl -X POST http://localhost:8080/api/tc/rules/egress \
  -H "Content-Type: application/json" \
  -d '{"ip_range":"8.8.8.8","port":53,"action":"deny"}'

# 获取出站规则
curl http://localhost:8080/api/tc/rules/egress

# 删除出站规则
curl -X DELETE "http://localhost:8080/api/tc/rules/egress?index=0"
```

### 统计信息
```bash
# 获取XDP流量统计
curl http://localhost:8080/api/stats

# 获取TC流量统计
curl http://localhost:8080/api/tc/stats

# 健康检查
curl http://localhost:8080/health
```

## BPF Maps

防火墙使用两套pinned maps：

### XDP Maps
- `whitelist_map`: 白名单规则（优先级最高）
- `blacklist_map`: 黑名单规则
- `stats_map`: 数据包统计信息
- `config_map`: 防火墙配置

### TC Maps
- `tc_ingress_map`: 入站流量规则
- `tc_egress_map`: 出站流量规则
- `tc_stats_map`: TC流量统计信息

## 架构设计

```
用户空间 Go 程序
    ↓
  eBPF Maps (规则存储)
    ↓    ↓
XDP 程序  TC 程序 (数据包过滤)
    ↓    ↓
  网络接口 (入站/出站)
```

### 核心组件

- **firewall.c**: XDP eBPF程序，负责XDP层数据包过滤
- **firewall_tc.c**: TC eBPF程序，负责TC层入站/出站流量控制
- **firewall.go**: Go语言管理接口，负责规则管理和统计（支持XDP和TC）
- **eBPF Maps**: 存储防火墙规则和统计信息（XDP和TC独立管理）

## 编译要求

- Go 1.21+
- clang 
- Linux内核支持eBPF和XDP
- root权限 (用于加载eBPF程序)

## 安装依赖

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install clang llvm

# CentOS/RHEL
sudo yum install clang llvm

# 确保内核支持XDP
uname -r  # 需要 4.8+ 版本
```

## 编译

```bash
cd bpf/firewall
go generate  # 生成eBPF绑定
go build     # 编译Go程序
```

## 使用示例

### 运行演示程序

```bash
# 需要root权限
sudo go run examples/firewall-demo/main.go -interface=eth0 -mode=demo
```

### 添加规则

```bash
# 添加白名单规则 - 允许192.168.1.0/24网段访问SSH
sudo go run examples/firewall-demo/main.go -mode=add-rule -type=whitelist -ip=192.168.1.0/24 -port=22 -protocol=6

# 添加黑名单规则 - 阻止10.0.0.100的所有流量  
sudo go run examples/firewall-demo/main.go -mode=add-rule -type=blacklist -ip=10.0.0.100 -port=0 -protocol=0

# 添加黑名单规则 - 阻止所有IP访问Telnet端口
sudo go run examples/firewall-demo/main.go -mode=add-rule -type=blacklist -ip=0.0.0.0/0 -port=23 -protocol=6
```

### 查看规则

```bash
sudo go run examples/firewall-demo/main.go -mode=list-rules
```

### 查看统计

```bash
sudo go run examples/firewall-demo/main.go -mode=stats
```

## API使用

```go
package main

import (
    "github.com/meimeitou/bgo/bpf/firewall"
)

func main() {
    // 创建防火墙实例
    fw, err := firewall.NewXDPFirewall("eth0")
    if err != nil {
        panic(err)
    }
    defer fw.Close()

    // 附加到网络接口
    if err := fw.Attach(); err != nil {
        panic(err)
    }
    defer fw.Detach()

    // 添加白名单规则
    err = fw.AddWhitelistRule("192.168.1.0/24", 22, firewall.ProtocolTCP)
    
    // 添加黑名单规则
    err = fw.AddBlacklistRule("10.0.0.100", 0, 0)
    
    // 获取统计信息
    stats, err := fw.GetStats()
    if err == nil {
        fmt.Printf("总数据包: %d, 允许: %d, 阻止: %d\n", 
            stats.TotalPackets, stats.AllowedPackets, stats.BlockedPackets)
    }
}
```

## 规则配置

### IP地址格式

- 单个IP: `192.168.1.100`
- CIDR网段: `192.168.1.0/24`
- 所有IP: `0.0.0.0/0`

### 端口配置

- 特定端口: `22`, `80`, `443`
- 所有端口: `0`

### 协议类型

- 所有协议: `0`
- TCP: `6`
- UDP: `17`

## 工作原理

1. **数据包接收**: XDP程序在网络驱动层接收数据包
2. **解析**: 解析以太网头、IP头和传输层头
3. **白名单检查**: 优先检查白名单，匹配则允许通过
4. **黑名单检查**: 检查黑名单，匹配则丢弃数据包
5. **默认动作**: 根据配置执行默认动作(允许/丢弃)
6. **统计更新**: 更新数据包统计信息

## 性能特点

- **零拷贝**: XDP在驱动层处理，避免数据包拷贝到用户空间
- **线性性能**: O(n)时间复杂度，n为规则数量
- **低延迟**: 微秒级别的处理延迟
- **高吞吐**: 支持百万级PPS处理能力

## 限制说明

- 最大支持100条白名单规则
- 最大支持100条黑名单规则
- 仅支持IPv4协议
- 需要root权限运行
- 需要内核支持XDP

## 故障排除

### 常见错误

1. **权限不足**
   ```
   Error: failed to attach XDP program: operation not permitted
   ```
   解决: 使用sudo运行

2. **内核不支持XDP**
   ```
   Error: XDP not supported
   ```
   解决: 升级内核到4.8+版本

3. **网络接口不存在**
   ```
   Error: failed to get interface: no such device
   ```
   解决: 检查网络接口名称

### 调试技巧

1. 使用`ip link`查看网络接口
2. 使用`dmesg`查看内核日志
3. 检查`/sys/kernel/debug/tracing/trace_pipe`获取eBPF调试信息

## 扩展功能

可以通过修改源码实现：

- 支持IPv6
- 更多协议支持
- 动态规则热更新
- 流量限制
- 地理位置过滤
- DDoS防护

## 许可证

GPL License - 详见LICENSE文件
