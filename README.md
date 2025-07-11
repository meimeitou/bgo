# bgo

一个基于 Go 和 eBPF 的系统工具集合

## 功能特性

- 📖 **bash readline 监控**: 使用 eBPF 技术监控 bash 命令行输入
- 🛡️ **统一防火墙**: 基于 eBPF 的高性能网络防火墙，同时支持 XDP 和 TC 两种模式
  - **XDP 模式**: 支持黑白名单过滤，数据包处理更早，性能更高
  - **TC 模式**: 支持入站/出站流量控制，可区分方向，功能更灵活
  - **协议过滤**: 支持 TCP/UDP/ICMP 协议级别的精确控制
- 🚀 **高性能**: 基于 eBPF 内核技术，低延迟高效率
- 📦 **易于使用**: 简单的命令行界面和 REST API
- 🔄 **持久化**: 支持 pinned BPF maps，规则重启后保持有效

## 快速开始

### 安装

```bash
git clone https://github.com/meimeitou/bgo.git
cd bgo
go build -o bgo .
```

### 使用

```bash
# 查看版本信息
./bin/bgo version

# 运行 bash readline 监控
./bin/bgo bashreadline

# 启动统一防火墙服务器 (需要 root 权限)
# 同时支持 XDP 和 TC 两种模式，提供 REST API
sudo ./bin/bgo firewall-server --interface enp0s3

# 管理 XDP 防火墙规则
# 添加白名单规则（允许本地网络访问 SSH）
sudo ./bin/bgo firewall-update --xdp --type whitelist --action add --ip 192.168.1.0/24 --port 22 --protocol tcp

# 添加黑名单规则（阻止特定IP）
sudo ./bin/bgo firewall-update --xdp --type blacklist --action add --ip 10.0.0.100

# 管理 TC 防火墙规则
# 添加入站规则（阻止特定IP访问SSH）
sudo ./bin/bgo firewall-update --action add --type blacklist --ip 192.168.1.100 --port 22 --protocol tcp --ingress

# 添加出站规则（阻止访问特定DNS服务器）
sudo ./bin/bgo firewall-update --action add --type blacklist --ip 8.8.8.8 --port 53 --protocol udp --egress

# 列出所有规则
sudo ./bin/bgo firewall-update --xdp --type whitelist --action list
sudo ./bin/bgo firewall-update --action list --type blacklist --ingress

# 查看统计信息
sudo ./bin/bgo firewall-update --xdp --action stats
sudo ./bin/bgo firewall-update --action stats --ingress
```

## 系统要求

- Linux 内核版本 >= 4.15 (支持 eBPF)
- Go 1.24+
- 管理员权限 (eBPF 程序需要)

## 项目结构

- `cmd/` - 命令行接口
- `bpf/` - eBPF 程序源码
- `lib/` - 依赖库 (libbpf, xdp-tools)

## 许可证

All rights reserved by meimeitou

## 统一防火墙详细说明

### XDP 模式
- **黑名单模式**: 阻止特定 IP/端口的访问
- **白名单模式**: 只允许特定 IP 段访问指定端口
- **优先级**: 白名单优先于黑名单
- **性能**: 在网络驱动层处理，性能最高

### TC 模式  
- **入站控制**: 控制进入网络接口的流量
- **出站控制**: 控制离开网络接口的流量
- **方向性**: 可精确控制流量方向
- **黑白名单**: 同样支持黑名单和白名单模式

### REST API
防火墙服务器提供 HTTP API 用于远程管理：

```bash
# XDP API - 管理白名单
curl -X POST http://localhost:8080/api/rules/whitelist \
  -H "Content-Type: application/json" \
  -d '{"ip_range":"192.168.1.0/24","port":22,"protocol":"tcp"}'

# XDP API - 管理黑名单  
curl -X POST http://localhost:8080/api/rules/blacklist \
  -H "Content-Type: application/json" \
  -d '{"ip_range":"10.0.0.100","port":0,"protocol":"any"}'

# TC API - 管理入站规则
curl -X POST http://localhost:8080/api/tc/rules/ingress \
  -H "Content-Type: application/json" \
  -d '{"ip_range":"192.168.1.100","port":22,"rule_type":"blacklist","protocol":"tcp"}'

# TC API - 管理出站规则
curl -X POST http://localhost:8080/api/tc/rules/egress \
  -H "Content-Type: application/json" \
  -d '{"ip_range":"8.8.8.8","port":53,"rule_type":"blacklist","protocol":"udp"}'

# 查看统计信息
curl http://localhost:8080/api/stats/xdp
curl http://localhost:8080/api/stats/tc/ingress
```

