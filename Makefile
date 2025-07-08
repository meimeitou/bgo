# Makefile for bgo - eBPF Go tool

# 项目信息
BINARY_NAME := bgo
PACKAGE := github.com/meimeitou/bgo
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# 构建目录
BUILD_DIR := bin
DIST_DIR := dist

# Go 参数
GO := go
GOFLAGS := -ldflags "-X '$(PACKAGE)/cmd.Version=$(VERSION)' -X '$(PACKAGE)/cmd.GitCommit=$(COMMIT)'"
TAGS := linux

# eBPF 相关
BPF_DIR := bpf
TOOLS_DIR := tools

.PHONY: all
all: deps-all clean generate build

# 构建二进制文件
.PHONY: build
build: generate
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -tags $(TAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# 生成 eBPF 代码
.PHONY: generate
generate:
	@echo "Generating eBPF code..."
	$(GO) generate ./...

# 安装依赖
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	$(GO) mod download
	$(GO) mod tidy

# 初始化 submodule
.PHONY: submodule-init
submodule-init:
	@echo "Initializing git submodules..."
	git submodule update --init --recursive

# 更新 submodule
.PHONY: submodule-update
submodule-update:
	@echo "Updating git submodules..."
	git submodule update --remote --recursive

# 重置 submodule
.PHONY: submodule-reset
submodule-reset:
	@echo "Resetting git submodules..."
	git submodule foreach --recursive git reset --hard HEAD
	git submodule update --init --recursive

# 检查 submodule 状态
.PHONY: submodule-status
submodule-status:
	@echo "Checking git submodules status..."
	git submodule status --recursive

# 完整的依赖安装 (包括submodule)
.PHONY: deps-all
deps-all: submodule-init deps
	@echo "All dependencies installed!"

# 运行测试
.PHONY: test
test:
	@echo "Running tests..."
	$(GO) test -v ./...

# 创建发布包
.PHONY: dist
dist: clean build
	@echo "Creating distribution package..."
	@mkdir -p $(DIST_DIR)
	@tar -czf $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)
	@echo "Distribution package created: $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz"

# 交叉编译
.PHONY: cross-compile
cross-compile: generate
	@echo "Cross compiling..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -tags $(TAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -tags $(TAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .

# 安装到系统
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME)..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "Installed to /usr/local/bin/$(BINARY_NAME)"

# 卸载
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)

# 清理
.PHONY: clean
clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@$(GO) clean

# 深度清理 (包括生成的文件)
.PHONY: clean-all
clean-all: clean
	@echo "Deep cleaning..."
	@find . -name "*_bpfel.go" -delete
	@find . -name "*_bpfel.o" -delete
	@find . -name "*_bpfeb.go" -delete
	@find . -name "*_bpfeb.o" -delete

# 检查系统要求
.PHONY: check-deps
check-deps:
	@echo "Checking system dependencies..."
	@echo "Go version: $$($(GO) version)"
	@echo "Kernel version: $$(uname -r)"
	@if [ ! -d "/sys/fs/bpf" ]; then \
		echo "WARNING: BPF filesystem not mounted. Run: sudo mount -t bpf bpf /sys/fs/bpf"; \
	fi
	@if ! command -v clang >/dev/null 2>&1; then \
		echo "WARNING: clang not found. Install with: sudo apt-get install clang"; \
	fi

# 显示帮助信息
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all              - Initialize submodules, clean, generate and build (default)"
	@echo "  build            - Build the binary"
	@echo "  generate         - Generate eBPF code"
	@echo "  deps             - Install Go dependencies"
	@echo "  deps-all         - Install all dependencies including submodules"
	@echo "  submodule-init   - Initialize git submodules"
	@echo "  submodule-update - Update git submodules"
	@echo "  submodule-reset  - Reset git submodules"
	@echo "  submodule-status - Check git submodules status"
	@echo "  test             - Run tests"
	@echo "  tools            - Build tools"
	@echo "  dist             - Create distribution package"
	@echo "  cross-compile    - Cross compile for multiple architectures"
	@echo "  install          - Install to /usr/local/bin"
	@echo "  uninstall        - Remove from /usr/local/bin"
	@echo "  clean            - Clean build artifacts"
	@echo "  clean-all        - Deep clean including generated files"
	@echo "  check-deps       - Check system dependencies"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Example usage:"
	@echo "  make deps-all    # Initialize submodules and install dependencies"
	@echo "  make build       # Build the binary"
	@echo "  make run         # Build and run"
	@echo "  sudo make install # Install system-wide"
	@echo "  make submodule-update # Update all submodules"

.DEFAULT_GOAL := help