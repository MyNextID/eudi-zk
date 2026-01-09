# Makefile for eudi-zk with Longfellow integration
.PHONY: all init test-cpp test-go test-all clean help

# Directories
LONGFELLOW_DIR := longfellow
CPP_DIR := $(LONGFELLOW_DIR)/cpp
BUILD_DIR := $(CPP_DIR)/build
VENDOR_DIR := $(LONGFELLOW_DIR)/vendor
LF_ZK_DIR := $(VENDOR_DIR)/longfellow-zk

# Get absolute paths
ROOT_DIR := $(shell pwd)
WRAPPER_LIB_DIR := $(ROOT_DIR)/$(BUILD_DIR)

# Compiler settings
CXX := clang++
CMAKE := cmake

# CGO flags for macOS Homebrew
export CGO_CFLAGS := -I/opt/homebrew/include
export CGO_LDFLAGS := -L/opt/homebrew/lib -L$(WRAPPER_LIB_DIR) -Wl,-rpath,$(WRAPPER_LIB_DIR)

# Go flags
VERSION ?= "0.4.0-dev"
COMMIT  ?= $(shell git rev-parse --short HEAD)
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -X github.com/mynextid/eudi-zk/server/api.Version=$(VERSION) \
           -X github.com/mynextid/eudi-zk/server/api.Commit=$(COMMIT) \
           -X github.com/mynextid/eudi-zk/server/api.BuildDate=$(DATE)


all: help

help:
	@echo "Available targets:"
	@echo "  build-zkpi     - Build Go ZKPI service"
	@echo "  install-zkpi   - Install Go ZKPI service"
	@echo "  test-go        - Run Go tests"
	@echo "  init           - Initialize submodules and dependencies"
	@echo "  build-wrapper  - Build C++ wrapper library"
	@echo "  test-cpp       - Run C++ tests"
	@echo "  test-all       - Run both C++ and Go tests"
	@echo "  test-quick     - Quick Go test without rebuild"
	@echo "  clean          - Clean build artifacts"

init:
	@echo "Initializing Longfellow-ZK submodule..."
	git submodule update --init --recursive
	@echo "Installing dependencies..."
	@echo "Make sure you have: clang, cmake, libssl-dev, libzstd-dev, googletest"

build-longfellow:
	@echo "Building Longfellow-ZK library..."
	cd $(LF_ZK_DIR) && \
	CXX=$(CXX) $(CMAKE) -D CMAKE_BUILD_TYPE=Release -S lib -B clang-build-release && \
	cd clang-build-release && make -j8

build-zkpi:
	@echo "Building Go ZKPI"
	go build -ldflags "$(LDFLAGS)" -o bin/zkpi ./cmd

install-zkpi:
	@echo "Installing Go ZKPI"
	go install -ldflags "$(LDFLAGS)" ./cmd

build-wrapper: build-longfellow
	@echo "Building C++ wrapper..."
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && \
	$(CMAKE) .. && \
	make -j8

# Run C++ tests
test-cpp: build-wrapper
	@echo "Running C++ tests..."
	@if [ -f "$(BUILD_DIR)/ecdsa_tests" ]; then \
		cd $(BUILD_DIR) && ./ecdsa_tests; \
	else \
		echo "Error: ecdsa_tests not found. Make sure CMakeLists.txt includes test target."; \
		exit 1; \
	fi

# List available C++ tests
test-cpp-list:
	@echo "Available C++ tests:"
	cd $(BUILD_DIR) && ./ecdsa_tests --gtest_list_tests

# Run Go tests
test-go:
	@echo "Running Go tests..."
	cd circuits && go test -v -timeout 30m ./...

# Run all tests (C++ and Go)
test-all: test-cpp test-go
	@echo "All tests completed!"

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf $(LF_ZK_DIR)/clang-build-release
	go clean -cache

# Quick test without full rebuild
# test-quick:
# 	go test -v ./longfellow/cgo/...

# Quick C++ test without rebuild
test-cpp-quick:
	@if [ -f "$(BUILD_DIR)/ecdsa_tests" ]; then \
		cd $(BUILD_DIR) && ./ecdsa_tests; \
	else \
		echo "Error: ecdsa_tests not found. Run 'make build-wrapper' first."; \
		exit 1; \
	fi
