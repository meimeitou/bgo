#!/bin/bash
# BGO 测试环境示例脚本
# 演示如何使用 testenv.sh 进行各种测试

set -e

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
TESTENV="$SCRIPT_DIR/testenv.sh"

echo "=== BGO 测试环境示例 ==="
echo ""

# 检查是否以 root 运行
if [ "$EUID" -ne 0 ]; then
    echo "请以 root 权限运行此脚本:"
    echo "sudo $0"
    exit 1
fi

echo "1. 创建测试环境..."
$TESTENV --legacy-ip --name demo-env setup

echo ""
echo "2. 查看环境状态..."
$TESTENV --name demo-env status

echo ""
echo "3. 测试网络连通性..."
$TESTENV --name demo-env ping -c 2

echo ""
echo "4. 添加防火墙规则 - 阻止 ping 8.8.8.8..."
$TESTENV --name demo-env bgo firewall-update \
  --action add --type blacklist \
  --ip 8.8.8.8 --protocol icmp

echo ""
echo "5. 查看防火墙规则..."
$TESTENV --name demo-env bgo firewall-update --action list

echo ""
echo "6. 查看防火墙统计..."
$TESTENV --name demo-env bgo firewall-update --action stats

echo ""
echo "7. 测试 BGO API..."
if $TESTENV --name demo-env curl -s http://localhost:8080/api/status > /dev/null 2>&1; then
    echo "API 可用，查看状态:"
    $TESTENV --name demo-env curl -s http://localhost:8080/api/status | head -5
else
    echo "Warning: BGO API 不可用"
fi

echo ""
echo "8. 进入测试环境 (按 Ctrl+D 退出)..."
echo "在环境中你可以运行:"
echo "  - ip addr show"
echo "  - ping 外部IP"
echo "  - curl http://localhost:8080/api/stats"
echo ""
$TESTENV --name demo-env enter

echo ""
echo "9. 清理环境..."
$TESTENV --name demo-env teardown

echo ""
echo "=== 示例完成 ==="
echo ""
echo "更多用法请参考 scripts/README.md"
