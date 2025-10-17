# BGO 文档中心

欢迎来到 BGO 项目的文档中心！这里包含了所有功能的使用说明和技术文档。

## 🚀 快速开始

**新用户推荐从这里开始：**

1. **[防火墙使用指南](FIREWALL_USAGE.md)** - 完整的 `firewall-update` 和 `firewall-ratelimit` 使用教程
2. **[防火墙命令速查表](FIREWALL_CHEATSHEET.md)** - 常用命令快速参考

## 📚 核心功能文档

### 防火墙规则管理

- **[防火墙使用指南](FIREWALL_USAGE.md)** 📘
  - `firewall-update` 完整使用说明
  - XDP 和 TC 模式介绍
  - 白名单/黑名单规则配置
  - 实际使用场景示例

- **[防火墙命令速查表](FIREWALL_CHEATSHEET.md)** 📋
  - 所有命令的快速参考
  - 常用参数和值
  - 一键复制的命令示例

### 流量限制

- **[流量限制功能详解](RATELIMIT.md)** 🔥
  - Rate Limiting 完整功能说明
  - PPS 和 BPS 限制原理
  - 令牌桶算法介绍
  - REST API 接口说明
  - 高级配置和调优

- **[流量限制快速入门](RATELIMIT_QUICKSTART.md)** ⚡
  - 5 分钟快速上手
  - 基本命令演示
  - 常见场景配置
  - 问题排查指南

### IP 地址和网络

- **[IP 范围支持说明](IP_RANGE_SUPPORT.md)** 🌐
  - CIDR 表示法详解
  - 单 IP 和 IP 段的使用
  - IP 范围测试和验证
  - CIDR 快速参考表

### 负载均衡

- **[LVS NAT 配置指南](../bpf/firewall/LVS_NAT_GUIDE.md)** 🔧
  - LVS DNAT 模式配置
  - VIP 和 RIP 设置
  - 连接跟踪说明
  - 完整部署示例

## 🏗️ 架构和设计文档

### Pin 机制

- **[Rate Limit Pin 管理](RATELIMIT_PIN_MANAGEMENT.md)** 
  - Pinned BPF maps 工作原理
  - `firewall-server` 如何管理 maps
  - `firewall-ratelimit` 如何访问 maps
  - 多网卡支持说明

- **[Interface 参数移除说明](INTERFACE_PARAM_REMOVAL.md)**
  - 为什么移除 `--interface` 参数
  - 架构优化的原因
  - 迁移指南
  - 正确的使用方式

- **[Interface 参数问题分析](INTERFACE_PARAMETER_ISSUE.md)**
  - 详细的问题分析
  - 设计决策过程
  - 备选方案对比

## 📖 使用场景

### 基础防护

```bash
# 场景 1：保护 SSH 服务
sudo ./bin/bgo firewall-update --xdp --type whitelist --action add \
  --ip 192.168.1.0/24 --port 22 --protocol tcp
```

详见：[防火墙使用指南 - 场景 1](FIREWALL_USAGE.md#场景-1保护-ssh-服务)

### DDoS 防护

```bash
# 场景 2：启用流量限制防止 DDoS
sudo ./bin/bgo firewall-ratelimit --enable --pps 5000 --bps 52428800
```

详见：[防火墙使用指南 - 场景 4](FIREWALL_USAGE.md#场景-4ddos-防护)

### 负载均衡

```bash
# 场景 3：配置 LVS DNAT
sudo ./bin/bgo firewall-lvs add-dnat --vip 192.168.63.100 --vport 80 \
  --rip 192.168.63.20 --rport 8080 --protocol tcp
```

详见：[LVS NAT 配置指南](../bpf/firewall/LVS_NAT_GUIDE.md)

## 🔍 快速查找

### 按命令查找

| 命令 | 文档 | 描述 |
|------|------|------|
| `firewall-server` | [使用指南](FIREWALL_USAGE.md) | 启动防火墙服务 |
| `firewall-update` | [使用指南](FIREWALL_USAGE.md) | 管理防火墙规则 |
| `firewall-ratelimit` | [使用指南](FIREWALL_USAGE.md), [详解](RATELIMIT.md) | 管理流量限制 |
| `firewall-lvs` | [LVS 指南](../bpf/firewall/LVS_NAT_GUIDE.md) | LVS 负载均衡 |

### 按主题查找

| 主题 | 相关文档 |
|------|---------|
| 白名单/黑名单 | [使用指南](FIREWALL_USAGE.md), [速查表](FIREWALL_CHEATSHEET.md) |
| 流量限制 | [详解](RATELIMIT.md), [快速入门](RATELIMIT_QUICKSTART.md) |
| IP 范围 | [IP 范围支持](IP_RANGE_SUPPORT.md) |
| XDP vs TC | [使用指南](FIREWALL_USAGE.md) |
| REST API | [流量限制详解](RATELIMIT.md) |
| 多网卡 | [使用指南](FIREWALL_USAGE.md), [Pin 管理](RATELIMIT_PIN_MANAGEMENT.md) |
| 负载均衡 | [LVS NAT 指南](../bpf/firewall/LVS_NAT_GUIDE.md) |

## 💡 提示和技巧

### 实时监控

```bash
# 监控防火墙统计
watch -n 1 'sudo ./bin/bgo firewall-update --xdp --action stats'

# 监控流量限制
watch -n 1 'sudo ./bin/bgo firewall-ratelimit --show-stats'
```

### 脚本化管理

```bash
# 批量添加规则
for IP in 192.168.1.{10..20}; do
  sudo ./bin/bgo firewall-update --xdp --type whitelist --action add --ip $IP
done
```

### 调试和排错

```bash
# 查看已 pinned 的 maps
ls -la /sys/fs/bpf/firewall/

# 检查 BPF 程序状态
sudo bpftool prog list
sudo bpftool map list
```

## 🆘 常见问题

### 规则不生效？

1. 确认 `firewall-server` 正在运行
2. 检查 pinned maps 是否存在：`ls /sys/fs/bpf/firewall/`
3. 查看统计信息：`sudo ./bin/bgo firewall-update --xdp --action stats`

详见：[防火墙使用指南 - 常见问题](FIREWALL_USAGE.md#常见问题)

### 流量被错误阻止？

1. 检查白名单/黑名单规则
2. 查看流量限制配置
3. 查看统计信息分析原因

详见：[流量限制快速入门 - 问题排查](RATELIMIT_QUICKSTART.md)

## 📞 获取帮助

- **命令帮助**：使用 `--help` 参数
  ```bash
  ./bin/bgo firewall-update --help
  ./bin/bgo firewall-ratelimit --help
  ```

- **示例脚本**：查看 `scripts/` 目录
  ```bash
  ls scripts/
  # demo.sh, demo_ratelimit.sh, testenv.sh
  ```

- **GitHub Issues**：[提交问题](https://github.com/meimeitou/bgo/issues)

## 🔄 文档更新

本文档持续更新中。最后更新：2025-10-17

---

**快速链接：**
- 🏠 [返回主页](../README.md)
- 📘 [防火墙使用指南](FIREWALL_USAGE.md)
- 📋 [命令速查表](FIREWALL_CHEATSHEET.md)
- 🔥 [流量限制详解](RATELIMIT.md)
