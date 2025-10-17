#!/bin/bash
# BGO 系统兼容性快速检查脚本

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== BGO 系统兼容性检查 ==="
echo ""

# 1. 内核版本
KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

echo "1. 内核版本: $KERNEL_VERSION"

if [ "$KERNEL_MAJOR" -gt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 4 ]); then
    echo -e "   ${GREEN}✅ 完全支持 (推荐)${NC}"
    KERNEL_OK=1
elif [ "$KERNEL_MAJOR" -gt 4 ] || ([ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -ge 18 ]); then
    echo -e "   ${YELLOW}⚠️  基本支持 (建议升级到 5.4+)${NC}"
    KERNEL_OK=1
else
    echo -e "   ${RED}❌ 不支持 (需要 >= 4.18)${NC}"
    KERNEL_OK=0
fi
echo ""

# 2. BPF支持
echo "2. BPF支持:"
BPF_OK=1

# 检查 CONFIG_BPF
if zgrep -q "CONFIG_BPF=y" /proc/config.gz 2>/dev/null || \
   grep -q "CONFIG_BPF=y" /boot/config-$(uname -r) 2>/dev/null; then
    echo -e "   ${GREEN}✅ CONFIG_BPF=y${NC}"
elif [ ! -f /proc/config.gz ] && [ ! -f /boot/config-$(uname -r) ]; then
    echo -e "   ${YELLOW}⚠️  无法检查内核配置 (假设已启用)${NC}"
else
    echo -e "   ${RED}❌ BPF未启用${NC}"
    BPF_OK=0
fi

# 检查 CONFIG_BPF_SYSCALL
if zgrep -q "CONFIG_BPF_SYSCALL=y" /proc/config.gz 2>/dev/null || \
   grep -q "CONFIG_BPF_SYSCALL=y" /boot/config-$(uname -r) 2>/dev/null; then
    echo -e "   ${GREEN}✅ CONFIG_BPF_SYSCALL=y${NC}"
elif [ ! -f /proc/config.gz ] && [ ! -f /boot/config-$(uname -r) ]; then
    : # 跳过
else
    echo -e "   ${RED}❌ BPF_SYSCALL未启用${NC}"
    BPF_OK=0
fi
echo ""

# 3. XDP支持
echo "3. XDP支持:"
if zgrep -q "CONFIG_XDP_SOCKETS=y" /proc/config.gz 2>/dev/null || \
   grep -q "CONFIG_XDP_SOCKETS=y" /boot/config-$(uname -r) 2>/dev/null; then
    echo -e "   ${GREEN}✅ CONFIG_XDP_SOCKETS=y${NC}"
elif [ ! -f /proc/config.gz ] && [ ! -f /boot/config-$(uname -r) ]; then
    echo -e "   ${YELLOW}⚠️  无法检查配置 (假设已启用)${NC}"
else
    echo -e "   ${YELLOW}⚠️  XDP_SOCKETS未启用（可能影响性能）${NC}"
fi
echo ""

# 4. TC支持
echo "4. TC支持:"
if zgrep -qE "CONFIG_NET_CLS_BPF=(y|m)" /proc/config.gz 2>/dev/null || \
   grep -qE "CONFIG_NET_CLS_BPF=(y|m)" /boot/config-$(uname -r) 2>/dev/null; then
    echo -e "   ${GREEN}✅ CONFIG_NET_CLS_BPF=y/m${NC}"
elif [ ! -f /proc/config.gz ] && [ ! -f /boot/config-$(uname -r) ]; then
    echo -e "   ${YELLOW}⚠️  无法检查配置 (假设已启用)${NC}"
else
    echo -e "   ${RED}❌ NET_CLS_BPF未启用${NC}"
fi
echo ""

# 5. BPF文件系统
echo "5. BPF文件系统:"
if mount | grep -q "bpf on /sys/fs/bpf"; then
    echo -e "   ${GREEN}✅ /sys/fs/bpf 已挂载${NC}"
elif [ -d /sys/fs/bpf ]; then
    echo -e "   ${YELLOW}⚠️  /sys/fs/bpf 未挂载${NC}"
    echo "   建议执行: sudo mount -t bpf bpf /sys/fs/bpf"
else
    echo -e "   ${RED}❌ /sys/fs/bpf 不存在${NC}"
fi
echo ""

# 6. 权限检查
echo "6. 权限检查:"
if [ "$EUID" -eq 0 ]; then
    echo -e "   ${GREEN}✅ 当前是root用户${NC}"
else
    echo -e "   ${YELLOW}⚠️  当前不是root用户，运行bgo需要sudo${NC}"
fi
echo ""

# 总结
echo "=== 检查完成 ==="
if [ "$KERNEL_OK" -eq 1 ] && [ "$BPF_OK" -eq 1 ]; then
    if [ "$KERNEL_MAJOR" -gt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 4 ]); then
        echo -e "${GREEN}✅ 您的系统完全支持 bgo 所有功能${NC}"
        exit 0
    else
        echo -e "${YELLOW}⚠️  您的系统可以运行 bgo，但建议升级内核到 5.4+ 以获得最佳性能${NC}"
        exit 0
    fi
else
    echo -e "${RED}❌ 您的系统不满足最小要求，请查看文档升级系统${NC}"
    echo "   文档: docs/KERNEL_REQUIREMENTS.md"
    exit 1
fi
