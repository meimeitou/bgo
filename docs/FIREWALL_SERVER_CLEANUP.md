# firewall-server 退出时的 BPF 资源管理

## 问题

**firewall-server 退出时是否会卸载掉 BPF 程序和 pinned maps？**

## 答案

### 简短回答

**部分卸载**：
- ✅ **BPF 程序会被卸载**（XDP 和 TC 程序从网卡上 detach）
- ✅ **Pinned maps 会保留**（数据持久化，规则和配置不丢失）

### 详细说明

## 1. BPF 程序（会卸载）

当 `firewall-server` 退出时（正常退出或收到 SIGINT/SIGTERM 信号），会执行以下清理操作：

### XDP 程序

```go
// cmd/firewall.go (line ~427-437)
func (s *FirewallServer) Cleanup(interfaceName string) error {
    // Detach XDP program
    if s.fw != nil {
        log.Printf("Detaching XDP program from interface %s...", interfaceName)
        if err := s.fw.Detach(); err != nil {
            log.Printf("Error detaching XDP program: %v", err)
        } else {
            log.Printf("XDP program detached from interface %s", interfaceName)
        }
    }
}
```

**结果**：
- ✅ XDP 程序从网卡上卸载
- ✅ 数据包不再被 XDP 程序处理
- ❌ XDP 过滤功能**停止工作**

### TC 程序

```go
// cmd/firewall.go (line ~445-455)
func (s *FirewallServer) Cleanup(interfaceName string) error {
    // Detach TC programs
    if s.tcManager != nil {
        log.Printf("Detaching TC programs from interface %s...", interfaceName)
        if err := s.tcManager.DetachPrograms(); err != nil {
            log.Printf("Error detaching TC programs: %v", err)
        } else {
            log.Printf("TC programs detached from interface %s", interfaceName)
        }
    }
}
```

**结果**：
- ✅ TC ingress 和 egress 程序被卸载
- ✅ TC filter 被删除
- ❌ TC 过滤功能**停止工作**

### 退出日志示例

```
2025/10/17 05:15:33 Received shutdown signal, shutting down firewall server...
2025/10/17 05:15:33 Firewall server stopped
2025/10/17 05:15:33 Starting firewall cleanup...
2025/10/17 05:15:33 Detaching XDP program from interface enp0s8...
2025/10/17 05:15:33 XDP program detached from interface enp0s8
2025/10/17 05:15:33 XDP firewall resources cleaned up
2025/10/17 05:15:33 Detaching TC programs from interface enp0s8...
Removed TC ingress filter (handle 1)
Removed TC egress filter (handle 1)
TC firewall programs detached from interface enp0s8
2025/10/17 05:15:33 TC programs detached from interface enp0s8
2025/10/17 05:15:33 TC firewall manager resources cleaned up
2025/10/17 05:15:33 Firewall cleanup completed
```

## 2. Pinned Maps（会保留）

**重要**：Pinned BPF maps **不会被删除**！

### 为什么 Maps 会保留？

因为 cilium/ebpf 库的 `Close()` 方法**只关闭文件描述符**，不会删除 pinned maps：

```go
// bpf/firewall/firewall.go (line ~310-322)
func (fw *XDPFirewall) Close() error {
    if err := fw.Detach(); err != nil {
        return err
    }

    if fw.objs != nil {
        fw.objs.Close()  // ← 只关闭 fd，不删除 pinned files
    }
    return nil
}
```

### 验证 Maps 保留

```bash
# 启动 server
$ sudo ./bin/bgo firewall-server start --interface eth0 &

# 添加规则
$ sudo ./bin/bgo firewall-update --xdp --type whitelist --action add \
    --ip 192.168.1.100 --port 22 --protocol tcp

# 停止 server（Ctrl+C 或 kill）
$ sudo kill -SIGINT <pid>

# 检查 pinned maps 是否还在
$ sudo ls -la /sys/fs/bpf/firewall/
drwxr-xr-x 2 root root 0 Oct 17 05:15 .
-rw------- 1 root root 0 Oct 17 05:15 blacklist_map           ← 还在！
-rw------- 1 root root 0 Oct 17 05:15 config_map              ← 还在！
-rw------- 1 root root 0 Oct 17 05:15 whitelist_map           ← 还在！
-rw------- 1 root root 0 Oct 17 05:15 rate_limit_config_map   ← 还在！
-rw------- 1 root root 0 Oct 17 05:15 tc_stats_map            ← 还在！
... (所有 maps 都还在)

# 查看规则是否还在 map 中
$ sudo ./bin/bgo firewall-update --xdp --action list
# 可以看到之前添加的规则！
```

### 保留的 Maps 列表

退出后以下 maps **仍然存在**：

**XDP Maps:**
- `whitelist_map` - 白名单规则
- `blacklist_map` - 黑名单规则
- `stats_map` - 统计信息
- `config_map` - 配置
- `rate_limit_config_map` - 流量限制配置
- `rate_limit_state_map` - 流量限制状态
- `rate_limit_stats_map` - 流量限制统计
- `lvs_dnat_map` - LVS DNAT 映射
- `conn_track_map` - 连接跟踪
- `conn_reverse_map` - 反向连接映射

**TC Maps:**
- `tc_stats_map` - TC 统计
- `tc_ingress_whitelist` - Ingress 白名单
- `tc_ingress_blacklist` - Ingress 黑名单
- `tc_egress_whitelist` - Egress 白名单
- `tc_egress_blacklist` - Egress 黑名单
- 以及对应的 count maps

## 3. 重启后的行为

### 重启 Server 后规则自动恢复

因为 maps 被保留，重新启动 server 时规则会自动恢复！

```bash
# 第一次启动
$ sudo ./bin/bgo firewall-server start --interface eth0 &

# 添加规则
$ sudo ./bin/bgo firewall-update --xdp --type whitelist --action add \
    --ip 192.168.1.100

# 停止 server
$ sudo kill -SIGINT <pid>

# --- Maps 仍然在文件系统中 ---

# 重新启动 server
$ sudo ./bin/bgo firewall-server start --interface eth0 &

# 规则自动恢复！无需重新添加
$ sudo ./bin/bgo firewall-update --xdp --action list
# 可以看到 192.168.1.100 的规则还在！
```

### 为什么规则会恢复？

因为 server 启动时会尝试加载已存在的 pinned maps：

```go
// bpf/firewall/firewall.go (line ~132-154)
func NewXDPFirewallWithPin(iface, pinPath string) (*XDPFirewall, error) {
    // ...
    if pinPath != "" {
        // Check if maps are already pinned
        if _, err := os.Stat(pinPath + "/whitelist_map"); err == nil {
            // Maps exist, load from pinned
            if err := fw.loadFromPinned(); err == nil {
                return fw, nil  // ← 使用已存在的 maps！
            }
        }
    }
    // Otherwise create new maps
    // ...
}
```

## 4. 实际影响

### 防火墙功能状态

| 状态 | XDP 程序 | TC 程序 | Pinned Maps | 防火墙功能 | 规则数据 |
|------|---------|---------|-------------|-----------|---------|
| **Server 运行中** | ✅ 已附加 | ✅ 已附加 | ✅ 存在 | ✅ **工作中** | ✅ 保留 |
| **Server 退出后** | ❌ 已卸载 | ❌ 已卸载 | ✅ 存在 | ❌ **不工作** | ✅ 保留 |
| **Server 重启后** | ✅ 已附加 | ✅ 已附加 | ✅ 存在 | ✅ **工作中** | ✅ 保留 |

### 关键要点

1. **防火墙功能停止**：
   - Server 退出后，XDP 和 TC 程序被卸载
   - 数据包不再被过滤
   - **网络恢复到无防火墙状态**

2. **配置数据保留**：
   - 所有规则、限制配置、统计信息保留在 pinned maps 中
   - 可以使用 `firewall-update` 和 `firewall-ratelimit` 查看和修改
   - 重启 server 后自动恢复

3. **无需重新配置**：
   - 重启 server 不需要重新添加规则
   - 规则从 pinned maps 自动加载
   - 配置持久化

## 5. 手动清理 Maps

如果需要完全清理（删除 pinned maps），使用 `cleanup-maps` 命令：

```bash
# 清理所有 pinned maps（会提示确认）
$ sudo ./bin/bgo firewall-server cleanup-maps

WARNING: This will remove all firewall configuration and statistics!
All pinned BPF maps at /sys/fs/bpf/firewall will be deleted.
This includes:
- Firewall rules (whitelist/blacklist)
- Rate limiting configuration
- Connection tracking data
- All statistics

Continue? (yes/no): yes

Removing pinned maps from /sys/fs/bpf/firewall...
Successfully removed all pinned maps
```

### 强制清理（不提示）

```bash
$ sudo ./bin/bgo firewall-server cleanup-maps --force
```

### 清理后的状态

```bash
$ sudo ls /sys/fs/bpf/firewall/
ls: cannot access '/sys/fs/bpf/firewall/': No such file or directory

# Maps 目录被删除，所有数据丢失
```

## 6. 最佳实践

### 正常使用

```bash
# ✅ 推荐：使用 systemd 管理 server
# 创建 systemd service 文件，确保 server 自动重启
$ sudo systemctl enable bgo-firewall
$ sudo systemctl start bgo-firewall

# Server 意外退出时会自动重启，规则自动恢复
```

### 临时停止防火墙

```bash
# 如果需要临时停止防火墙（保留配置）
$ sudo killall bgo

# 规则仍在 maps 中，随时可以重启恢复
$ sudo ./bin/bgo firewall-server start --interface eth0
```

### 完全清理

```bash
# 如果需要完全清理防火墙（删除所有配置）
$ sudo killall bgo  # 停止 server
$ sudo ./bin/bgo firewall-server cleanup-maps --force  # 删除 maps
```

## 7. 对比其他防火墙

### iptables
```bash
# iptables 规则在内存中，重启系统会丢失
# 需要使用 iptables-save/iptables-restore 持久化
```

### nftables
```bash
# nftables 规则在内存中，重启系统会丢失
# 需要手动保存和恢复配置
```

### bgo firewall
```bash
# ✅ Pinned maps 自动持久化
# ✅ 重启 server 自动恢复规则
# ✅ 无需手动保存/恢复
```

## 总结

| 资源类型 | Server 退出后 | 说明 |
|---------|--------------|------|
| **XDP 程序** | ❌ 被卸载 | 防火墙功能停止 |
| **TC 程序** | ❌ 被卸载 | 防火墙功能停止 |
| **Pinned Maps** | ✅ **保留** | 规则和配置持久化 |
| **防火墙规则** | ✅ **保留** | 存储在 maps 中 |
| **流量限制配置** | ✅ **保留** | 存储在 maps 中 |
| **统计信息** | ✅ **保留** | 存储在 maps 中 |

**关键要点**：
- 🔴 **Server 退出 = 防火墙功能停止**（程序卸载）
- 🟢 **Maps 保留 = 配置不丢失**（数据持久化）
- 🔵 **Server 重启 = 功能自动恢复**（从 maps 加载）

这是一个**优秀的设计**，结合了：
- ✅ 安全性（退出时卸载程序）
- ✅ 便利性（配置自动持久化）
- ✅ 可靠性（重启后自动恢复）
