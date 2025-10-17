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
- 📖 **bash readline 监控**: 实时监控 bash 命令行输入，用于审计和安全分析
- � **磁盘 I/O 监控 (biosnoop)**: 跟踪块设备 I/O 操作，分析磁盘性能和延迟

### 网络安全
- �🛡️ **统一防火墙**: 基于 eBPF 的高性能网络防火墙，支持多种过滤模式
  - **XDP 模式**: 在网络驱动层处理，性能最优，支持黑白名单过滤
  - **TC 模式**: 支持入站/出站流量精确控制，功能更灵活
  - **协议过滤**: 支持 TCP/UDP/ICMP 协议级别的精确控制
  - **REST API**: 提供 HTTP API 接口，便于集成和自动化管理

### 技术特性
- 🔄 **持久化**: 支持 pinned BPF maps，确保配置重启后保持有效
- 📦 **统一接口**: 所有功能通过统一的命令行工具访问
- 🌐 **API 集成**: 防火墙功能提供完整的 REST API 支持

## 文档

### 快速上手
- 📘 [防火墙使用指南](docs/FIREWALL_USAGE.md) - 完整的功能使用说明
- 📋 [防火墙命令速查表](docs/FIREWALL_CHEATSHEET.md) - 常用命令快速参考

### 详细文档
- 🔥 [流量限制功能](docs/RATELIMIT.md) - Rate Limiting 详细说明
- ⚡ [流量限制快速入门](docs/RATELIMIT_QUICKSTART.md) - Rate Limiting 快速开始
- 🌐 [IP 范围支持](docs/IP_RANGE_SUPPORT.md) - CIDR 和 IP 段使用
- 🔧 [LVS NAT 配置指南](bpf/firewall/LVS_NAT_GUIDE.md) - 负载均衡配置

### 架构说明
- 🏗️ [Rate Limit Pin 管理](docs/RATELIMIT_PIN_MANAGEMENT.md) - Pin 机制说明
- 🔄 [Interface 参数移除](docs/INTERFACE_PARAM_REMOVAL.md) - 架构优化说明

## 系统要求

### 最小内核版本

| 功能 | 最小版本 | 推荐版本 |
|------|---------|---------|
| **防火墙 + 限流** | Linux 4.18 | Linux 5.4+ |
| **完整功能** | Linux 5.4 | Linux 5.10+ |

详细信息请查看：
- 📋 [内核要求详解](docs/KERNEL_REQUIREMENTS.md)
- 🚀 [部署指南](docs/DEPLOYMENT.md)

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
go build -o bin/bgo .
```

### 查看可用命令

```bash
# 查看所有可用命令
./bin/bgo --help

# 查看特定命令的详细帮助
./bin/bgo bashreadline --help
./bin/bgo biosnoop --help
./bin/bgo firewall-server --help
```

### 基本用法示例

```bash
# 查看版本信息
./bin/bgo version

# 监控 bash 命令输入
sudo ./bin/bgo bashreadline

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

## 项目结构

```
bgo/
├── cmd/           # 命令行接口实现
├── bpf/           # eBPF 程序源码
│   ├── bashreadline/  # bash 监控功能
│   ├── biosnoop/      # 磁盘 I/O 监控功能
│   └── firewall/      # 防火墙功能
├── lib/           # 依赖库 (libbpf, xdp-tools)
├── pkg/           # 通用包
└── scripts/       # 辅助脚本
```

## 贡献指南

我们欢迎社区贡献！请参考以下步骤：

1. Fork 本项目
2. 创建功能分支 (`git checkout -b feature/new-feature`)
3. 提交变更 (`git commit -am 'Add new feature'`)
4. 推送分支 (`git push origin feature/new-feature`)
5. 创建 Pull Request

## 许可证

本项目采用 Apache License 2.0 许可证 - 详细信息请查看 [LICENSE](LICENSE) 文件。

```
Copyright 2025 meimeitou

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
