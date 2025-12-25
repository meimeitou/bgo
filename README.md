# bgo

一个基于 Go 和 eBPF 的现代系统监控与安全工具集合

## 核心优势

- 🚀 **高性能**: 基于 eBPF 内核技术，在内核空间直接处理数据，极低的性能开销
- 🔒 **安全可靠**: 利用 eBPF 的安全机制，确保程序运行的安全性和稳定性
- 📊 **实时监控**: 提供实时的系统和网络监控能力，无需修改内核或安装内核模块
- 🛠️ **易于部署**: 单一二进制文件，无复杂依赖，快速部署和使用
- 🔧 **模块化设计**: 每个功能独立实现，可根据需求选择使用

## 功能特性

### 系统监控
- � **磁盘 I/O 监控 (biosnoop)**: 跟踪块设备 I/O 操作，分析磁盘性能和延迟


### 技术特性
- 🔄 **持久化**: 支持 pinned BPF maps，确保配置重启后保持有效
- 📦 **统一接口**: 所有功能通过统一的命令行工具访问
- 🌐 **API 集成**: 防火墙功能提供完整的 REST API 支持

## 系统要求

### 最小内核版本

| 功能 | 最小版本 | 推荐版本 |
|------|---------|---------|
| **防火墙 + 限流** | Linux 4.18 | Linux 5.4+ |
| **完整功能** | Linux 5.4 | Linux 5.10+ |

### 快速检查

```bash
# 检查系统兼容性
./scripts/check_system.sh
```

## 快速开始

### 构建项目

```bash
git clone https://github.com/meimeitou/bgo.git
cd bgo
make build
```


### 基本用法示例

```bash
# 查看版本信息
./bin/bgo version

# 监控磁盘 I/O 活动
sudo ./bin/bgo biosnoop

# 启动防火墙服务器
sudo ./bin/bgo firewall-server start --interface enp0s9

# 启用 LVS 功能
sudo ./bin/bgo firewall-lvs enable

# 添加防火墙规则
sudo ./bin/bgo firewall-lvs add-dnat --vip 192.168.63.100 --vport 80 --rip 192.168.63.20 --rport 8080 --protocol tcp
# 网卡添加ip地址
sudo ip addr add 192.168.63.100/24 dev enp0s8
# 删除ip: sudo ip addr del 192.168.63.100/24 dev enp0s8

```

> **注意**: 大部分功能需要 root 权限，因为 eBPF 程序需要加载到内核空间。各命令的详细使用说明请使用 `--help` 参数查看。

## 系统要求

- Linux 内核版本 >= 4.15 (支持 eBPF)
- Go 1.19+ 
- 管理员权限 (eBPF 程序需要)
