# bgo

一个基于 Go 和 eBPF 的系统工具集合

## 功能特性

- 🚀 **高性能**: 基于 eBPF 内核技术，低延迟高效率
- 📦 **易于使用**: 简单的命令行界面

## 快速开始

### 安装

```bash
git clone https://github.com/meimeitou/bgo.git
cd bgo
go build -o bgo .
```

### 使用

```bash
# 查看版本信息
./bgo version

# 运行 bash readline 监控
./bgo bashreadline
```

## 系统要求

- Linux 内核版本 >= 4.15 (支持 eBPF)
- Go 1.24+
- 管理员权限 (eBPF 程序需要)

## 项目结构

- `cmd/` - 命令行接口
- `bpf/` - eBPF 程序源码
- `lib/` - 依赖库 (libbpf, xdp-tools)

## 许可证

All rights reserved by meimeitou

