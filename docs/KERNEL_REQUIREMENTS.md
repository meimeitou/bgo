# BGO 内核版本要求详解

## 快速参考

### 最小内核版本

如果只使用**防火墙规则和限流功能**，最小内核要求为：

| 发行版 | 默认内核 | 是否支持 | 备注 |
|--------|----------|----------|------|
| **Ubuntu 20.04+** | 5.4+ | ✅ 完全支持 | 推荐使用 |
| **Ubuntu 18.04 HWE** | 5.4+ | ✅ 完全支持 | 需安装 HWE 内核 |
| **Ubuntu 18.04** | 4.15 | ⚠️ 部分支持 | 建议升级到 HWE |
| **Debian 11+** | 5.10+ | ✅ 完全支持 | 推荐使用 |
| **Debian 10** | 4.19 | ⚠️ 基本支持 | 建议升级内核 |
| **CentOS/RHEL 8** | 4.18 | ✅ 完全支持 | 包含 backport 特性 |
| **CentOS/RHEL 7** | 3.10 | ❌ **不支持** | 必须升级内核 |
| **Fedora 32+** | 5.6+ | ✅ 完全支持 | 推荐使用 |

### 推荐内核版本

- **最小可用**: Linux 4.18
- **推荐生产**: Linux 5.4 LTS
- **最佳性能**: Linux 5.10+ LTS

## 功能与内核版本对应关系

### 核心功能要求

| 功能模块 | 最小内核 | BPF特性依赖 | 说明 |
|----------|----------|------------|------|
| **XDP防火墙** | 4.18 | XDP基础支持 | 基本的包过滤 |
| **XDP Generic模式** | 4.12 | XDP Generic fallback | 虚拟网卡兼容 |
| **XDP Native模式** | 取决于网卡驱动 | 驱动级XDP支持 | 高性能模式 |
| **TC防火墙** | 4.16 | cls_bpf, act_bpf | Ingress/Egress过滤 |
| **白名单/黑名单** | 4.15 | BPF Array Map | IP/端口规则匹配 |
| **限流（令牌桶）** | 4.18 | bpf_ktime_get_ns | PPS/BPS限流 |
| **统计功能** | 4.15 | Atomic operations | 包/字节统计 |
| **Map Pinning** | 4.15 | BPF FS | 规则持久化 |

### BPF Helper函数要求

bgo使用的主要BPF helper函数及其最小内核版本：

```c
// 基础功能
bpf_map_lookup_elem()        // 3.19+ (基础)
bpf_map_update_elem()        // 3.19+ (基础)
bpf_ktime_get_ns()           // 4.1+  (时间戳)
bpf_trace_printk()           // 4.1+  (调试)

// 网络相关
bpf_redirect()               // 4.4+  (XDP重定向)
bpf_clone_redirect()         // 4.2+  (包克隆)

// 原子操作（限流统计）
__sync_fetch_and_add()       // 4.15+ (原子加法)
```

## 详细版本说明

### Linux 4.15 - 4.17
**基本支持，但不推荐生产环境**

✅ 可用功能：
- 基础BPF maps
- 简单的XDP程序
- 基础TC过滤
- Map pinning

❌ 限制：
- XDP性能较差
- 某些BPF verifier限制
- 可能不支持令牌桶精确限流

### Linux 4.18 - 4.19
**最小推荐版本**

✅ 新增支持：
- 改进的BPF verifier
- 更好的XDP性能
- 完整的令牌桶限流支持
- BTF（BPF Type Format）初步支持

⚠️ 注意事项：
- CentOS/RHEL 8 使用 4.18 内核，但包含大量 5.x 特性 backport
- 生产环境建议使用 5.4+

### Linux 5.4 LTS
**推荐生产环境版本** ⭐

✅ 主要优势：
- 稳定的BPF子系统
- 完整的XDP功能
- 优秀的性能
- 长期支持（至2025年12月）
- Ubuntu 20.04 / Debian 11 默认内核

✅ 全功能支持：
- 所有防火墙规则
- 精确限流
- 完整统计
- Map pinning
- BTF支持

### Linux 5.10 LTS
**最佳选择** ⭐⭐⭐

✅ 进一步改进：
- 更强大的BPF verifier
- 更好的JIT编译
- 完整的CO-RE (Compile Once, Run Everywhere)
- Ring buffer支持
- 长期支持（至2026年12月）

### Linux 5.15+ LTS
**未来推荐**

✅ 最新特性：
- 进一步性能优化
- 更多BPF helper函数
- 改进的错误提示
- 长期支持（至2027年10月）

## 检查当前系统

### 1. 检查内核版本

```bash
# 查看内核版本
uname -r

# 查看完整内核信息
uname -a

# 查看发行版信息
cat /etc/os-release
```

### 2. 检查BPF支持

```bash
# 方法1: 检查内核配置
zgrep CONFIG_BPF /proc/config.gz 2>/dev/null || \
  grep CONFIG_BPF /boot/config-$(uname -r) 2>/dev/null

# 应该看到：
# CONFIG_BPF=y
# CONFIG_BPF_SYSCALL=y
# CONFIG_BPF_JIT=y
# CONFIG_XDP_SOCKETS=y

# 方法2: 检查BPF文件系统
mount | grep bpf
# 应该看到：bpf on /sys/fs/bpf type bpf

# 方法3: 尝试加载简单BPF程序
sudo bpftool prog list
# 如果成功执行说明BPF支持正常
```

### 3. 检查XDP支持

```bash
# 检查网卡是否支持XDP
ip link show

# 查看XDP配置选项
zgrep XDP /proc/config.gz 2>/dev/null || \
  grep XDP /boot/config-$(uname -r) 2>/dev/null

# 应该看到：
# CONFIG_XDP_SOCKETS=y
# CONFIG_XDP_SOCKETS_DIAG=y (可选)
```

### 4. 检查TC支持

```bash
# 检查TC BPF支持
zgrep "NET_CLS_BPF\|NET_SCH" /proc/config.gz 2>/dev/null || \
  grep "NET_CLS_BPF\|NET_SCH" /boot/config-$(uname -r) 2>/dev/null

# 应该看到：
# CONFIG_NET_CLS_BPF=y (或 =m)
# CONFIG_NET_SCH_INGRESS=y (或 =m)

# 检查tc命令是否可用
tc -Version
```

### 5. 完整兼容性测试

```bash
#!/bin/bash
# bgo_check_system.sh - 系统兼容性检查脚本

echo "=== BGO 系统兼容性检查 ==="
echo ""

# 1. 内核版本
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
echo "1. 内核版本: $(uname -r)"

if (( $(echo "$KERNEL_VERSION >= 5.4" | bc -l) )); then
    echo "   ✅ 完全支持 (推荐)"
elif (( $(echo "$KERNEL_VERSION >= 4.18" | bc -l) )); then
    echo "   ⚠️  基本支持 (建议升级到 5.4+)"
else
    echo "   ❌ 不支持 (需要 >= 4.18)"
    exit 1
fi
echo ""

# 2. BPF支持
echo "2. BPF支持:"
if zgrep -q "CONFIG_BPF=y" /proc/config.gz 2>/dev/null || \
   grep -q "CONFIG_BPF=y" /boot/config-$(uname -r) 2>/dev/null; then
    echo "   ✅ CONFIG_BPF=y"
else
    echo "   ❌ BPF未启用"
    exit 1
fi

if zgrep -q "CONFIG_BPF_SYSCALL=y" /proc/config.gz 2>/dev/null || \
   grep -q "CONFIG_BPF_SYSCALL=y" /boot/config-$(uname -r) 2>/dev/null; then
    echo "   ✅ CONFIG_BPF_SYSCALL=y"
else
    echo "   ❌ BPF_SYSCALL未启用"
    exit 1
fi
echo ""

# 3. XDP支持
echo "3. XDP支持:"
if zgrep -q "CONFIG_XDP_SOCKETS=y" /proc/config.gz 2>/dev/null || \
   grep -q "CONFIG_XDP_SOCKETS=y" /boot/config-$(uname -r) 2>/dev/null; then
    echo "   ✅ CONFIG_XDP_SOCKETS=y"
else
    echo "   ⚠️  XDP_SOCKETS未启用（可能影响性能）"
fi
echo ""

# 4. TC支持
echo "4. TC支持:"
if zgrep -qE "CONFIG_NET_CLS_BPF=(y|m)" /proc/config.gz 2>/dev/null || \
   grep -qE "CONFIG_NET_CLS_BPF=(y|m)" /boot/config-$(uname -r) 2>/dev/null; then
    echo "   ✅ CONFIG_NET_CLS_BPF=y/m"
else
    echo "   ❌ NET_CLS_BPF未启用"
fi
echo ""

# 5. BPF文件系统
echo "5. BPF文件系统:"
if mount | grep -q "bpf on /sys/fs/bpf"; then
    echo "   ✅ /sys/fs/bpf 已挂载"
else
    echo "   ⚠️  /sys/fs/bpf 未挂载"
    echo "   建议执行: sudo mount -t bpf bpf /sys/fs/bpf"
fi
echo ""

# 6. 权限检查
echo "6. 权限检查:"
if [ "$EUID" -eq 0 ]; then
    echo "   ✅ 当前是root用户"
else
    echo "   ⚠️  当前不是root用户，运行bgo需要sudo"
fi
echo ""

echo "=== 检查完成 ==="
if (( $(echo "$KERNEL_VERSION >= 5.4" | bc -l) )); then
    echo "✅ 您的系统完全支持 bgo 所有功能"
elif (( $(echo "$KERNEL_VERSION >= 4.18" | bc -l) )); then
    echo "⚠️  您的系统可以运行 bgo，但建议升级内核到 5.4+ 以获得最佳性能"
else
    echo "❌ 您的系统不满足最小要求，请升级内核"
fi
```

保存为 `bgo_check_system.sh`，执行：
```bash
chmod +x bgo_check_system.sh
./bgo_check_system.sh
```

## 升级内核指南

### Ubuntu 18.04 升级到 HWE 内核

```bash
# 安装 HWE (Hardware Enablement) 内核 - 包含 5.4
sudo apt update
sudo apt install --install-recommends linux-generic-hwe-18.04
sudo reboot

# 验证
uname -r  # 应该显示 5.4.x
```

### Debian 10 升级内核

```bash
# 添加 backports
echo "deb http://deb.debian.org/debian buster-backports main" | \
  sudo tee /etc/apt/sources.list.d/backports.list

# 更新并安装新内核
sudo apt update
sudo apt install -t buster-backports linux-image-amd64
sudo reboot

# 验证
uname -r
```

### CentOS/RHEL 7 升级内核

```bash
# 导入 ELRepo GPG key
sudo rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org

# 安装 ELRepo
sudo yum install https://www.elrepo.org/elrepo-release-7.el7.elrepo.noarch.rpm

# 安装长期支持内核 (推荐)
sudo yum --enablerepo=elrepo-kernel install kernel-lt

# 或安装最新主线内核
# sudo yum --enablerepo=elrepo-kernel install kernel-ml

# 设置新内核为默认
sudo grub2-set-default 0
sudo grub2-mkconfig -o /boot/grub2/grub.cfg

# 重启
sudo reboot

# 验证
uname -r
```

## 常见问题

### Q1: 我的内核是 4.18，bgo 能用吗？
**A**: 可以，所有防火墙和限流功能都支持。但推荐升级到 5.4+ 以获得更好的性能和稳定性。

### Q2: CentOS 8 的内核是 4.18，为什么说完全支持？
**A**: CentOS 8 虽然内核版本号是 4.18，但Red Hat backport了大量 5.x 的BPF特性，实际BPF功能接近 5.4 内核。

### Q3: 如何确认我的内核支持BPF？
**A**: 运行上面的系统检查脚本，或手动检查：
```bash
zgrep CONFIG_BPF /proc/config.gz 2>/dev/null || \
  grep CONFIG_BPF /boot/config-$(uname -r)
```

### Q4: 虚拟机中XDP性能不好，怎么办？
**A**: 虚拟机网卡通常只支持XDP Generic模式，性能较差。这是正常的，生产环境建议使用物理机或支持硬件XDP的云服务器。

### Q5: 需要重新编译内核吗？
**A**: 通常不需要。主流发行版的内核默认启用了BPF支持。只有极少数精简版系统需要重新编译。

## 总结

### 最小要求
- **内核版本**: Linux 4.18+
- **推荐版本**: Linux 5.4 LTS
- **最佳选择**: Linux 5.10+ LTS

### 快速决策

```
你的内核 >= 5.4?
├─ 是 → ✅ 完美，直接使用
└─ 否 → 你的内核 >= 4.18?
         ├─ 是 → ⚠️  可用，但建议升级
         └─ 否 → ❌ 必须升级内核
```

对于生产环境，**强烈推荐使用 Linux 5.4 LTS 或更高版本**，以确保最佳性能和稳定性。
