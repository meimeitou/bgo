# 防火墙命令速查表

## 启动服务

```bash
sudo ./bin/bgo firewall-server start --interface eth0
```

---

## firewall-update（规则管理）

### 添加规则

```bash
# 白名单：允许 IP
sudo ./bin/bgo firewall-update --xdp --type whitelist --action add --ip 192.168.1.100

# 白名单：允许 IP 段的 SSH
sudo ./bin/bgo firewall-update --xdp --type whitelist --action add \
  --ip 192.168.1.0/24 --port 22 --protocol tcp

# 黑名单：阻止 IP
sudo ./bin/bgo firewall-update --xdp --type blacklist --action add --ip 10.0.0.50

# 黑名单：阻止 IP 段
sudo ./bin/bgo firewall-update --xdp --type blacklist --action add --ip 10.0.0.0/8
```

### 查看规则

```bash
# 查看所有规则
sudo ./bin/bgo firewall-update --xdp --action list

# 只看白名单
sudo ./bin/bgo firewall-update --xdp --type whitelist --action list

# 只看黑名单
sudo ./bin/bgo firewall-update --xdp --type blacklist --action list
```

### 删除规则

```bash
# 先查看规则索引
sudo ./bin/bgo firewall-update --xdp --type whitelist --action list

# 删除指定索引的规则
sudo ./bin/bgo firewall-update --xdp --type whitelist --action remove --index 0
```

### 查看统计

```bash
sudo ./bin/bgo firewall-update --xdp --action stats
```

---

## firewall-ratelimit（流量限制）

### 启用限制

```bash
# PPS + BPS
sudo ./bin/bgo firewall-ratelimit --enable --pps 1000 --bps 1048576

# 只限制 PPS
sudo ./bin/bgo firewall-ratelimit --enable --pps 10000

# 只限制 BPS（10 MB/s）
sudo ./bin/bgo firewall-ratelimit --enable --bps 10485760
```

### 查看配置

```bash
sudo ./bin/bgo firewall-ratelimit --show-config
```

### 查看统计

```bash
sudo ./bin/bgo firewall-ratelimit --show-stats
```

### 重置统计

```bash
sudo ./bin/bgo firewall-ratelimit --reset-stats
```

### 禁用限制

```bash
sudo ./bin/bgo firewall-ratelimit --disable
```

---

## TC 模式（入站/出站）

### Ingress（入站）

```bash
# 添加入站白名单
sudo ./bin/bgo firewall-update --action add --type whitelist \
  --ip 192.168.1.100 --port 22 --protocol tcp --ingress

# 查看入站规则
sudo ./bin/bgo firewall-update --action list --ingress

# 查看入站统计
sudo ./bin/bgo firewall-update --action stats --ingress
```

### Egress（出站）

```bash
# 添加出站黑名单
sudo ./bin/bgo firewall-update --action add --type blacklist \
  --ip 8.8.8.8 --port 53 --protocol udp --egress

# 查看出站规则
sudo ./bin/bgo firewall-update --action list --egress

# 查看出站统计
sudo ./bin/bgo firewall-update --action stats --egress
```

---

## 实时监控

```bash
# 监控防火墙统计
watch -n 1 'sudo ./bin/bgo firewall-update --xdp --action stats'

# 监控流量限制
watch -n 1 'sudo ./bin/bgo firewall-ratelimit --show-stats'
```

---

## 常用值参考

### 协议

- `tcp` - TCP
- `udp` - UDP
- `icmp` - ICMP (ping)
- `any` - 所有（默认）

### IP 格式

- 单个 IP：`192.168.1.100`
- IP 段：`192.168.1.0/24`、`10.0.0.0/8`

### BPS 换算

- 1 MB/s = `1048576`
- 10 MB/s = `10485760`
- 50 MB/s = `52428800`
- 100 MB/s = `104857600`

---

## 完整示例

```bash
# 1. 启动服务
sudo ./bin/bgo firewall-server start --interface eth0

# 2. 添加白名单（允许公司网段）
sudo ./bin/bgo firewall-update --xdp --type whitelist --action add \
  --ip 192.168.1.0/24 --port 22 --protocol tcp

# 3. 添加黑名单（阻止恶意 IP）
sudo ./bin/bgo firewall-update --xdp --type blacklist --action add \
  --ip 10.0.0.50

# 4. 启用流量限制
sudo ./bin/bgo firewall-ratelimit --enable --pps 5000 --bps 10485760

# 5. 查看效果
sudo ./bin/bgo firewall-update --xdp --action stats
sudo ./bin/bgo firewall-ratelimit --show-stats
```
