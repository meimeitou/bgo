# BGO 部署指南

## 二进制文件依赖

`make build` 构建的 `bgo` 二进制文件是**动态链接**的可执行文件，只依赖标准系统库：

```bash
$ ldd ./bin/bgo
    linux-vdso.so.1 (虚拟动态共享对象)
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (标准C库)
    /lib64/ld-linux-x86-64.so.2 (动态链接器)
```

这些依赖在所有现代Linux发行版中都是**默认安装的**，无需额外安装。

## 部署到新环境

### 1. 最小要求

#### 必需的系统依赖

**不同功能的最小内核版本要求：**

| 功能 | 最小内核版本 | 推荐版本 | 说明 |
|------|-------------|----------|------|
| **基础防火墙（XDP）** | **4.18** | 5.4+ | XDP程序、基本过滤规则 |
| **TC防火墙（Ingress/Egress）** | **4.16** | 5.4+ | 双向流量过滤 |
| **限流功能** | **4.18** | 5.4+ | 令牌桶算法限流 |
| **统计功能** | **4.15** | 5.4+ | 原子操作统计 |
| **BPF Maps Pin** | **4.15** | 5.4+ | Map持久化 |
| **所有功能稳定运行** | **5.4** | **5.10+** | 推荐生产环境版本 |

**内核配置要求：**
- 必须启用 BPF 支持
  - `CONFIG_BPF=y`
  - `CONFIG_BPF_SYSCALL=y`
  - `CONFIG_BPF_JIT=y` (推荐，提升性能)
- XDP 支持
  - `CONFIG_XDP_SOCKETS=y`
  - `CONFIG_BPF_EVENTS=y`
- TC (Traffic Control) 支持
  - `CONFIG_NET_CLS_BPF=y` 或 `CONFIG_NET_CLS_BPF=m`
  - `CONFIG_NET_SCH_INGRESS=y` 或 `CONFIG_NET_SCH_INGRESS=m`
  
**其他系统依赖：**
- **标准C库**: glibc 2.27+ (通常已安装)

- **BPF文件系统**: `/sys/fs/bpf` 必须挂载
  ```bash
  # 检查是否挂载
  mount | grep /sys/fs/bpf
  
  # 如果未挂载，执行：
  sudo mount -t bpf bpf /sys/fs/bpf
  ```

#### 所需权限
- **root权限** 或 **CAP_BPF + CAP_NET_ADMIN** capabilities
- 用于加载BPF程序和操作网络设备

### 2. 部署步骤

#### 方式一：直接复制二进制文件（推荐）

```bash
# 1. 在构建机器上
cd /path/to/bgo
make build

# 2. 复制到目标机器
scp ./bin/bgo target-host:/usr/local/bin/

# 3. 在目标机器上
sudo chmod +x /usr/local/bin/bgo

# 4. 验证
bgo version
```

#### 方式二：使用发行包

```bash
# 1. 在构建机器上创建发行包
make dist

# 2. 复制到目标机器
scp dist/bgo-*.tar.gz target-host:/tmp/

# 3. 在目标机器上解压
cd /tmp
tar xzf bgo-*.tar.gz
sudo cp bgo /usr/local/bin/
```

### 3. 验证部署

```bash
# 检查二进制文件
file /usr/local/bin/bgo
# 输出：ELF 64-bit LSB executable, x86-64...

# 检查依赖
ldd /usr/local/bin/bgo
# 应该只显示标准系统库

# 检查内核支持
uname -r  # 内核版本
zgrep CONFIG_BPF /proc/config.gz 2>/dev/null || grep CONFIG_BPF /boot/config-$(uname -r)
# 应该显示 CONFIG_BPF=y

# 检查BPF文件系统
mount | grep bpf
# 应该显示：bpf on /sys/fs/bpf type bpf

# 测试运行
sudo bgo version
```

### 4. 不同发行版的兼容性

#### ✅ 完全兼容（开箱即用）
- **Ubuntu** 20.04+ (内核 5.4+)
- **Ubuntu** 18.04 HWE (内核 5.4+)
- **Debian** 11+ (内核 5.10+)
- **CentOS/RHEL** 8+ (内核 4.18+)
- **Fedora** 32+ (内核 5.6+)
- **Rocky Linux** 8+ (内核 4.18+)
- **AlmaLinux** 8+ (内核 4.18+)

**注意**: CentOS/RHEL 8 虽然内核版本是 4.18，但包含了大量 backport 的 BPF 特性，可以支持 bgo 的所有功能。

#### ⚠️ 需要额外配置

- **Ubuntu 18.04 LTS** (默认内核 4.15): 建议升级到 HWE 内核
  ```bash
  # 安装 HWE 内核（Hardware Enablement，包含 5.4 内核）
  sudo apt update
  sudo apt install --install-recommends linux-generic-hwe-18.04
  sudo reboot
  ```

- **Debian 10** (默认内核 4.19): 建议从 backports 安装新内核
  ```bash
  # 添加 backports 源
  echo "deb http://deb.debian.org/debian buster-backports main" | sudo tee /etc/apt/sources.list.d/backports.list
  sudo apt update
  
  # 从 backports 安装较新内核
  sudo apt install -t buster-backports linux-image-amd64
  sudo reboot
  ```

- **CentOS/RHEL 7** (内核 3.10): **必须**升级内核
  ```bash
  # 安装 ELRepo
  sudo rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
  sudo yum install https://www.elrepo.org/elrepo-release-7.el7.elrepo.noarch.rpm
  
  # 安装长期支持内核（推荐 5.4 LTS）
  sudo yum --enablerepo=elrepo-kernel install kernel-lt
  
  # 或安装最新主线内核
  sudo yum --enablerepo=elrepo-kernel install kernel-ml
  
  # 设置新内核为默认启动
  sudo grub2-set-default 0
  sudo reboot
  ```

- **Alpine Linux**: 需要安装 glibc
  ```bash
  # 安装 gcompat (glibc兼容层)
  apk add gcompat
  ```

### 5. 常见问题

#### Q1: 提示 "Operation not permitted"
**原因**: 缺少权限  
**解决**: 使用 `sudo` 或添加 capabilities
```bash
# 方式1: 使用 sudo
sudo bgo firewall-server start --interface eth0

# 方式2: 添加 capabilities（允许非root用户运行）
sudo setcap cap_bpf,cap_net_admin+ep /usr/local/bin/bgo
```

#### Q2: 提示 "BPF program load failed"
**原因**: 内核不支持BPF或未启用相关选项  
**解决**: 检查内核版本和配置
```bash
uname -r  # 需要 >= 5.4
zgrep BPF /proc/config.gz
```

#### Q3: `/sys/fs/bpf` 不存在
**原因**: BPF文件系统未挂载  
**解决**: 手动挂载
```bash
sudo mkdir -p /sys/fs/bpf
sudo mount -t bpf bpf /sys/fs/bpf

# 永久挂载（添加到 /etc/fstab）
echo "bpf /sys/fs/bpf bpf defaults 0 0" | sudo tee -a /etc/fstab
```

#### Q4: 提示 "libc.so.6: version GLIBC_2.XX not found"
**原因**: 目标系统的 glibc 版本太低  
**解决方案**:
1. **升级系统 glibc**（推荐）
2. **静态编译** bgo（见下文）

### 6. 静态编译（用于旧系统）

如果目标系统 glibc 版本过低，可以构建静态链接的二进制文件：

```bash
# 修改 Makefile，添加静态链接标志
GOFLAGS := -ldflags "-X '$(PACKAGE)/cmd.Version=$(VERSION)' -X '$(PACKAGE)/cmd.GitCommit=$(COMMIT)' -extldflags '-static'"

# 或者直接构建
CGO_ENABLED=0 go build -ldflags "-X 'github.com/meimeitou/bgo/cmd.Version=$(git describe --tags --always)' -extldflags '-static'" -o bin/bgo-static .

# 验证（静态编译后不应有依赖）
ldd bin/bgo-static
# 输出：not a dynamic executable
```

**注意**: 静态编译会增加二进制文件大小（~20-30MB），但可以在任何Linux系统上运行。

### 7. 容器化部署

如果使用容器，可以创建最小化镜像：

```dockerfile
# Dockerfile.bgo
FROM alpine:latest

# 安装必要的运行时依赖
RUN apk add --no-cache gcompat libelf

# 复制二进制文件
COPY bin/bgo /usr/local/bin/bgo

# 需要特权模式运行
# docker run --privileged --network host bgo firewall-server start
```

```bash
# 构建镜像
docker build -f Dockerfile.bgo -t bgo:latest .

# 运行（需要特权模式和主机网络）
docker run --privileged --network host -v /sys/fs/bpf:/sys/fs/bpf bgo:latest firewall-server start --interface eth0
```

## 总结

### ✅ 优点
- **零额外依赖**: 只需标准系统库
- **单文件部署**: 复制一个可执行文件即可
- **跨发行版兼容**: 适用于大多数现代Linux发行版

### ⚠️ 注意事项
- 必须有 **root权限** 或相应的 capabilities
- 内核版本 **>= 5.4**，推荐 5.10+
- 需要 **BPF文件系统** 支持
- 目标系统的 **CPU架构** 必须匹配（当前构建为 x86_64）

### 📝 快速部署检查清单
- [ ] 内核版本 >= 5.4
- [ ] BPF支持已启用
- [ ] `/sys/fs/bpf` 已挂载
- [ ] 有root权限或BPF/NET_ADMIN capabilities
- [ ] glibc >= 2.27（运行 `ldd --version` 检查）
- [ ] 二进制文件已复制并设置可执行权限
- [ ] 防火墙/SELinux未阻止BPF操作
