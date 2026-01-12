# Makefile for eudi-zk with Longfellow integration
.PHONY: all init test-cpp test-go test-all clean help

# Configuration - User can set USE_DYNE=1 to use Dyne's longfellow-zk instead of Google's
USE_DYNE ?= 0

# Detect platform for Dyne build
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Darwin)
    ifeq ($(UNAME_M),arm64)
        DYNE_TARGET := osx-arm64
    else
        DYNE_TARGET := posix
    endif
else
    DYNE_TARGET := posix
endif

# Directories
LONGFELLOW_DIR := longfellow
CPP_DIR := $(LONGFELLOW_DIR)/cpp
BUILD_DIR := $(CPP_DIR)/build
VENDOR_DIR := $(LONGFELLOW_DIR)/vendor

# Google's Longfellow-ZK (original/default)
LF_ZK_GOOGLE_DIR := $(VENDOR_DIR)/longfellow-zk
LF_ZK_GOOGLE_BUILD := $(LF_ZK_GOOGLE_DIR)/clang-build-release

# Dyne's Longfellow-ZK (alternative)
# Note: Dyne's version builds into src/ directory
LF_ZK_DYNE_DIR := $(VENDOR_DIR)/longfellow-zk-dyne
LF_ZK_DYNE_LIB := $(LF_ZK_DYNE_DIR)/src

# Get absolute paths
ROOT_DIR := $(shell pwd)
WRAPPER_LIB_DIR := $(ROOT_DIR)/$(BUILD_DIR)

# Compiler settings
CXX := clang++
CMAKE := cmake

# Select library paths based on USE_DYNE flag
ifeq ($(USE_DYNE),1)
    LF_ZK_DIR := $(LF_ZK_DYNE_DIR)
    LF_ZK_BUILD_DIR := $(LF_ZK_DYNE_LIB)
    LF_ZK_LIB_DIR := $(ROOT_DIR)/$(LF_ZK_DYNE_LIB)
    LF_ZK_INCLUDE := -I$(ROOT_DIR)/$(LF_ZK_DYNE_DIR)/src
    LF_ZK_LIB_NAME := longfellow-zk
    LF_ZK_LIB_FILE := $(LF_ZK_DYNE_LIB)/liblongfellow-zk.a
    $(info =====================================)
    $(info Using DYNE Longfellow-ZK library)
    $(info Target: $(DYNE_TARGET))
    $(info =====================================)
else
    LF_ZK_DIR := $(LF_ZK_GOOGLE_DIR)
    LF_ZK_BUILD_DIR := $(LF_ZK_GOOGLE_BUILD)
    LF_ZK_LIB_DIR := $(ROOT_DIR)/$(LF_ZK_GOOGLE_BUILD)
    LF_ZK_INCLUDE := -I$(ROOT_DIR)/$(LF_ZK_GOOGLE_DIR)/lib
    LF_ZK_LIB_NAME := longfellow_zk
    LF_ZK_LIB_FILE := $(LF_ZK_GOOGLE_BUILD)/liblongfellow_zk.a
    $(info =====================================)
    $(info Using GOOGLE Longfellow-ZK library)
    $(info =====================================)
endif

# CGO flags - dynamically set based on selected library
export CGO_CFLAGS := -I/opt/homebrew/include $(LF_ZK_INCLUDE) -I$(ROOT_DIR)/$(CPP_DIR)/include
export CGO_LDFLAGS := -L/opt/homebrew/lib -L$(LF_ZK_LIB_DIR) -l$(LF_ZK_LIB_NAME) -L$(WRAPPER_LIB_DIR) -Wl,-rpath,$(WRAPPER_LIB_DIR) -Wl,-rpath,$(LF_ZK_LIB_DIR)

# Add zstd for Dyne's version
ifeq ($(USE_DYNE),1)
export CGO_LDFLAGS += -L$(ROOT_DIR)/$(LF_ZK_DYNE_DIR)/vendor/zstd/lib -lzstd
endif

# Go flags
VERSION ?= "0.4.0-dev"
COMMIT  ?= $(shell git rev-parse --short HEAD)
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X github.com/mynextid/eudi-zk/server/api.Version=$(VERSION) \
           -X github.com/mynextid/eudi-zk/server/api.Commit=$(COMMIT) \
           -X github.com/mynextid/eudi-zk/server/api.BuildDate=$(DATE)

all: help

help:
	@echo "============================================"
	@echo "EUDI-ZK Makefile"
	@echo "============================================"
	@echo ""
	@echo "Build targets:"
	@echo "  build-zkpi           - Build Go ZKPI service with selected library"
	@echo "  install-zkpi         - Install Go ZKPI service"
	@echo "  build-wrapper        - Build C++ wrapper library"
	@echo "  build-longfellow     - Build selected Longfellow-ZK library"
	@echo "  build-all            - Build both libraries and wrapper"
	@echo ""
	@echo "Test targets:"
	@echo "  test-go              - Run Go tests with selected library"
	@echo "  test-cpp             - Run C++ wrapper tests"
	@echo "  test-longfellow      - Run Longfellow-ZK tests (selected version)"
	@echo "  test-all             - Run all tests"
	@echo ""
	@echo "Setup targets:"
	@echo "  init                 - Initialize Google's Longfellow-ZK (default)"
	@echo "  init-dyne            - Initialize Dyne's Longfellow-ZK"
	@echo "  init-all             - Initialize both versions"
	@echo ""
	@echo "Cleanup targets:"
	@echo "  clean                - Clean wrapper build artifacts"
	@echo "  clean-google         - Clean Google's Longfellow-ZK build"
	@echo "  clean-dyne           - Clean Dyne's Longfellow-ZK build"
	@echo "  clean-all            - Clean all build artifacts"
	@echo ""
	@echo "Configuration:"
	@echo "  USE_DYNE=0           - Use Google's Longfellow-ZK (default)"
	@echo "  USE_DYNE=1           - Use Dyne's Longfellow-ZK"
	@echo ""
	@echo "Platform: $(UNAME_S) $(UNAME_M)"
	@echo "Dyne target: $(DYNE_TARGET)"
	@echo ""
	@echo "Examples:"
	@echo "  make build-zkpi                  # Build with Google's library"
	@echo "  make USE_DYNE=1 build-zkpi       # Build with Dyne's library"
	@echo "  make USE_DYNE=1 test-go          # Test with Dyne's library"
	@echo "  make show-config                 # Show current configuration"
	@echo "  make check-libs                  # Check installed libraries"
	@echo ""

init:
	@echo "Initializing Google's Longfellow-ZK submodule..."
	git submodule update --init --recursive $(LF_ZK_GOOGLE_DIR)
	@echo "Installing dependencies..."
	@echo "Make sure you have: clang, cmake, libssl-dev, libzstd-dev, googletest"

init-dyne:
	@echo "Initializing Dyne's Longfellow-ZK..."
	@if [ ! -d "$(LF_ZK_DYNE_DIR)" ]; then \
		echo "Adding Dyne's Longfellow-ZK as submodule..."; \
		git submodule add https://github.com/dyne/longfellow-zk.git $(LF_ZK_DYNE_DIR); \
	fi
	git submodule update --init --recursive $(LF_ZK_DYNE_DIR)
	@echo "Dyne's Longfellow-ZK initialized at $(LF_ZK_DYNE_DIR)"

init-all: init init-dyne
	@echo "All Longfellow-ZK versions initialized!"

build-longfellow:
	@echo "Building $(if $(filter 1,$(USE_DYNE)),Dyne's,Google's) Longfellow-ZK library..."
ifeq ($(USE_DYNE),1)
	@# Build Dyne's version using GNUmakefile
	@echo "Using Dyne's GNUmakefile with target: $(DYNE_TARGET)"
	cd $(LF_ZK_DYNE_DIR) &&$(MAKE) import-vendor && $(MAKE) $(DYNE_TARGET) CXX=$(CXX) CC=$(CC)
	@if [ -f "$(LF_ZK_LIB_FILE)" ]; then \
		echo "✓ Library built successfully at: $(LF_ZK_LIB_FILE)"; \
	else \
		echo "✗ Error: Library not found at expected location: $(LF_ZK_LIB_FILE)"; \
		exit 1; \
	fi
else
	@# Build Google's version using CMake
	cd $(LF_ZK_GOOGLE_DIR) && \
	CXX=$(CXX) $(CMAKE) -D CMAKE_BUILD_TYPE=Release -S lib -B clang-build-release && \
	cd clang-build-release && make -j8
	@if [ -f "$(LF_ZK_LIB_FILE)" ]; then \
		echo "✓ Library built successfully at: $(LF_ZK_LIB_FILE)"; \
	else \
		echo "✗ Error: Library not found at expected location: $(LF_ZK_LIB_FILE)"; \
		exit 1; \
	fi
endif
	@echo "Longfellow-ZK build completed!"

build-wrapper: build-longfellow
	@echo "Building C++ wrapper..."
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && \
	$(CMAKE) -DLF_ZK_DIR=$(LF_ZK_DIR) \
	         -DLF_ZK_BUILD_DIR=$(LF_ZK_BUILD_DIR) \
	         -DUSE_DYNE=$(USE_DYNE) \
	         .. && \
	make -j8

build-all: build-longfellow build-wrapper
	@echo "All builds completed!"

build-zkpi: build-wrapper
	@echo "Building Go ZKPI with $(if $(filter 1,$(USE_DYNE)),Dyne's,Google's) Longfellow-ZK..."
	@echo "Library directory: $(LF_ZK_LIB_DIR)"
	@echo "CGO_LDFLAGS: $(CGO_LDFLAGS)"
	go build -ldflags "$(LDFLAGS)" -o bin/zkpi ./cmd

install-zkpi: build-wrapper
	@echo "Installing Go ZKPI with $(if $(filter 1,$(USE_DYNE)),Dyne's,Google's) Longfellow-ZK..."
	go install -ldflags "$(LDFLAGS)" ./cmd

# Run C++ wrapper tests
test-cpp: build-wrapper
	@echo "Running C++ wrapper tests..."
	@if [ -f "$(BUILD_DIR)/ecdsa_tests" ]; then \
		cd $(BUILD_DIR) && ./ecdsa_tests; \
	else \
		echo "Error: ecdsa_tests not found. Make sure CMakeLists.txt includes test target."; \
		exit 1; \
	fi

# Run Longfellow-ZK tests (selected version)
test-longfellow: build-longfellow
	@echo "Running $(if $(filter 1,$(USE_DYNE)),Dyne's,Google's) Longfellow-ZK tests..."
ifeq ($(USE_DYNE),1)
	@echo "Note: Dyne's version has tests in test/ directory"
	@if [ -d "$(LF_ZK_DYNE_DIR)/test" ]; then \
		echo "Test sources available, but no standalone test target in GNUmakefile"; \
		echo "Tests should be run via wrapper tests or integrated tests"; \
	fi
else
	@echo "Google's Longfellow-ZK: Run wrapper tests with 'make test-cpp'"
endif

# List available tests
test-cpp-list:
	@echo "Available C++ wrapper tests:"
	@if [ -f "$(BUILD_DIR)/ecdsa_tests" ]; then \
		cd $(BUILD_DIR) && ./ecdsa_tests --gtest_list_tests; \
	else \
		echo "Error: ecdsa_tests not found. Run 'make build-wrapper' first."; \
	fi

# Run Go tests with selected library
test-go: build-wrapper
	@echo "Running Go tests with $(if $(filter 1,$(USE_DYNE)),Dyne's,Google's) Longfellow-ZK..."
	cd circuits && go test -v -timeout 30m ./...

# Run all tests
test-all: test-cpp test-longfellow test-go
	@echo "All tests completed!"

clean:
	@echo "Cleaning C++ wrapper build artifacts..."
	rm -rf $(BUILD_DIR)
	go clean -cache

clean-google:
	@echo "Cleaning Google's Longfellow-ZK build..."
	rm -rf $(LF_ZK_GOOGLE_BUILD)

clean-dyne:
	@echo "Cleaning Dyne's Longfellow-ZK build..."
	cd $(LF_ZK_DYNE_DIR) && $(MAKE) clean || true

clean-all: clean clean-google clean-dyne
	@echo "All build artifacts cleaned!"

# Quick tests without rebuild
test-cpp-quick:
	@if [ -f "$(BUILD_DIR)/ecdsa_tests" ]; then \
		cd $(BUILD_DIR) && ./ecdsa_tests; \
	else \
		echo "Error: ecdsa_tests not found. Run 'make build-wrapper' first."; \
		exit 1; \
	fi

# Show current configuration
show-config:
	@echo "============================================"
	@echo "Current Configuration"
	@echo "============================================"
	@echo "USE_DYNE           = $(USE_DYNE)"
	@echo "Active library     = $(if $(filter 1,$(USE_DYNE)),Dyne's Longfellow-ZK,Google's Longfellow-ZK)"
	@echo "Platform           = $(UNAME_S) $(UNAME_M)"
	@echo "Dyne build target  = $(DYNE_TARGET)"
	@echo ""
	@echo "Paths:"
	@echo "  Library dir      = $(LF_ZK_DIR)"
	@echo "  Build dir        = $(LF_ZK_BUILD_DIR)"
	@echo "  Library path     = $(LF_ZK_LIB_DIR)"
	@echo "  Library file     = $(LF_ZK_LIB_FILE)"
	@echo "  Library name     = $(LF_ZK_LIB_NAME)"
	@echo "  Wrapper dir      = $(BUILD_DIR)"
	@echo ""
	@echo "CGO Configuration:"
	@echo "  CGO_CFLAGS       = $(CGO_CFLAGS)"
	@echo "  CGO_LDFLAGS      = $(CGO_LDFLAGS)"
	@echo ""
	@echo "Versions:"
	@echo "  Google's path    = $(LF_ZK_GOOGLE_DIR)"
	@echo "  Dyne's path      = $(LF_ZK_DYNE_DIR)"
	@echo "============================================"

# Check which libraries are available
check-libs:
	@echo "============================================"
	@echo "Checking available Longfellow-ZK libraries"
	@echo "============================================"
	@echo ""
	@echo "Google's Longfellow-ZK:"
	@if [ -d "$(LF_ZK_GOOGLE_DIR)" ] && [ -f "$(LF_ZK_GOOGLE_DIR)/README.md" ]; then \
		echo "  Status: ✓ INSTALLED"; \
		echo "  Path:   $(LF_ZK_GOOGLE_DIR)"; \
		if [ -f "$(LF_ZK_GOOGLE_BUILD)/liblongfellow_zk.a" ]; then \
			echo "  Built:  ✓ YES ($(LF_ZK_GOOGLE_BUILD)/liblongfellow_zk.a)"; \
		else \
			echo "  Built:  ✗ NO (run 'make build-longfellow')"; \
		fi; \
	else \
		echo "  Status: ✗ NOT INSTALLED"; \
		echo "  Action: Run 'make init'"; \
	fi
	@echo ""
	@echo "Dyne's Longfellow-ZK:"
	@if [ -d "$(LF_ZK_DYNE_DIR)" ] && [ -f "$(LF_ZK_DYNE_DIR)/README.md" ]; then \
		echo "  Status: ✓ INSTALLED"; \
		echo "  Path:   $(LF_ZK_DYNE_DIR)"; \
		if [ -f "$(LF_ZK_DYNE_LIB)/liblongfellow-zk.a" ]; then \
			echo "  Built:  ✓ YES ($(LF_ZK_DYNE_LIB)/liblongfellow-zk.a)"; \
		else \
			echo "  Built:  ✗ NO (run 'make USE_DYNE=1 build-longfellow')"; \
		fi; \
	else \
		echo "  Status: ✗ NOT INSTALLED"; \
		echo "  Action: Run 'make init-dyne'"; \
	fi
	@echo ""
	@echo "============================================"
	@echo "Currently selected: $(if $(filter 1,$(USE_DYNE)),Dyne's,Google's) Longfellow-ZK"
	@echo "Platform: $(UNAME_S) $(UNAME_M) → Dyne target: $(DYNE_TARGET)"
	@echo "Change with: make USE_DYNE=$(if $(filter 1,$(USE_DYNE)),0,1) <target>"
	@echo "============================================"