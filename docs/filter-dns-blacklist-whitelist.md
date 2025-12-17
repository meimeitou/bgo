# Filter DNS with IP Blacklist/Whitelist

## 功能说明

`filter-dns` 命令现在支持基于 IP 地址的黑白名单过滤功能，支持 IPv4 和 IPv6 地址。

### 主要特性

- ✅ **IPv4 和 IPv6 支持**：同时支持 IPv4 和 IPv6 地址过滤
- ✅ **高性能 Hash Map**：使用 eBPF hash map 实现快速 IP 查找
- ✅ **白名单模式**：只允许白名单中的 IP 发送/接收 DNS 流量
- ✅ **黑名单模式**：拒绝黑名单中的 IP 发送/接收 DNS 流量
- ✅ **灵活的文件格式**：支持纯文本和 CSV 格式
- ✅ **错误容忍**：自动跳过格式错误的 IP 地址

## 使用方法

### 基本用法

```bash
# 不使用黑白名单（默认行为）
sudo ./bin/bgo filter-dns --interface eth0

# 使用白名单
sudo ./bin/bgo filter-dns --interface eth0 --whitelist whitelist.txt

# 使用黑名单
sudo ./bin/bgo filter-dns --interface eth0 --blacklist blacklist.csv

# 带统计信息
sudo ./bin/bgo filter-dns --interface eth0 --whitelist whitelist.txt --stats
```

### IP 列表文件格式

支持两种文件格式：

#### 1. 纯文本格式

```
# 注释行以 # 开头
192.168.1.1
192.168.1.100
10.0.0.1

# IPv6 地址
2001:4860:4860::8888
2001:4860:4860::8844
```

#### 2. CSV 格式

```
# IP 地址, 备注
192.168.1.1, 允许的客户端1
192.168.1.100, DNS 服务器
10.0.0.1, 网关

# IPv6
2001:4860:4860::8888, Google DNS
```

**注意**：
- 每行一个 IP 地址
- 以 `#` 开头的行被视为注释
- CSV 格式只使用第一列（IP 地址），其他列会被忽略
- 无效的 IP 地址会被自动跳过
- 支持分隔符：逗号 `,`、分号 `;`、制表符 `\t`

## 工作模式

### 1. 无黑白名单模式（默认）

只允许 DNS 流量（端口 53）通过，丢弃其他所有流量。

```bash
sudo ./bin/bgo filter-dns --interface eth0
```

### 2. 白名单模式

- 只允许白名单中的 IP 地址访问 DNS 服务
- 所有其他 IP 的 DNS 请求将被拒绝
- 非 DNS 流量仍然会被拒绝

```bash
sudo ./bin/bgo filter-dns --interface eth0 --whitelist allowed_ips.txt
```

### 3. 黑名单模式

- 拒绝黑名单中的 IP 地址访问 DNS 服务
- 其他 IP 的 DNS 请求正常通过
- 非 DNS 流量仍然会被拒绝

```bash
sudo ./bin/bgo filter-dns --interface eth0 --blacklist blocked_ips.csv
```

## 统计信息

使用 `--stats` 参数可以实时查看过滤统计：

```bash
sudo ./bin/bgo filter-dns --interface eth0 --whitelist whitelist.txt --stats --interval 3
```

统计信息包括：
- **Total packets**: 处理的总数据包数
- **DNS packets**: 通过的 DNS 数据包数
- **Dropped packets**: 丢弃的数据包总数
- **Whitelist allowed**: 白名单允许的数据包数（白名单模式）
- **Whitelist dropped**: 白名单拒绝的数据包数（白名单模式）
- **Blacklist dropped**: 黑名单拒绝的数据包数（黑名单模式）

## 示例文件

项目包含两个示例文件：

### example_whitelist.txt
白名单示例，包含常见的 DNS 服务器和本地网络地址。

### example_blacklist.csv
黑名单示例（CSV 格式），展示如何添加备注信息。

## 性能特点

- 使用 eBPF XDP（eXpress Data Path）技术在内核层面过滤数据包
- Hash map 查找时间复杂度 O(1)
- 支持最多 10,000 个 IPv4 和 10,000 个 IPv6 地址
- 零拷贝、极低延迟

## 限制说明

- 不能同时使用黑名单和白名单
- 每个列表最大支持 10,000 个 IP 地址
- 需要 root 权限运行
- 需要内核支持 XDP

## 错误处理

程序会自动跳过以下情况：
- 空行
- 注释行（以 `#` 开头）
- 格式错误的 IP 地址
- 无效的 IP 地址格式

所有被跳过的条目会在加载时统计并显示。

## 技术实现

- **BPF Maps**: 使用 4 个 hash map 分别存储 IPv4/IPv6 的黑白名单
- **网络字节序**: 自动处理字节序转换
- **原子操作**: 统计计数使用原子操作保证准确性
- **零拷贝**: 直接在 XDP 层面处理数据包，无需拷贝到用户态
