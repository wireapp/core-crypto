# Makefile: Always run Cargo steps, but only re-run downstream generators when inputs change

.PHONY: help
# Parse the comment starting with a double ## next to a target as the target description
# in the help message
help: ## Show this help message
	@grep -E '^[a-zA-Z0-9_.-]+:.*?## ' $(MAKEFILE_LIST) | \
		sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

SHELL := /usr/bin/env bash

# Only build in release mode if explicitly requested by
# setting the `RELEASE` variable to any non-empty value, e.g.
#
#   make wasm RELEASE=1
#
# This will also optimize the Wasm binary.
ifeq ($(RELEASE),)
  CARGO_BUILD_ARGS :=
  XCODE_CONFIG := Debug
  RELEASE_MODE := debug
else
  CARGO_BUILD_ARGS := --release
  XCODE_CONFIG := Release
  RELEASE_MODE := release
endif

TARGET_DIR := target/$(RELEASE_MODE)

# Detect host platform for NDK and library extensions
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  PLATFORM_DIR       := linux-x86_64
  LIBRARY_EXTENSION  := so
else ifeq ($(UNAME_S),Darwin)
  PLATFORM_DIR       := darwin-x86_64
  LIBRARY_EXTENSION  := dylib
else
  $(error Unsupported host platform $(UNAME_S))
endif

# Setup Android toolchain
# Preferred NDK version
ANDROID_NDK_PREFER_VERSION ?= 28.1

# Autodetect or use existing NDK_HOME/NDK_HOME
ANDROID_NDK_ROOT = $(strip \
  $(or \
    $(ANDROID_NDK_HOME), \
    $(NDK_HOME), \
    $(shell [ -d "$(HOME)/Android/Sdk/ndk" ] && \
               find "$(HOME)/Android/Sdk/ndk" -maxdepth 1 -type d \
                    -name "$(ANDROID_NDK_PREFER_VERSION)*" \
               | head -n1) \
  ) \
)


# Build paths
NDK_TOOLCHAIN := $(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/$(HOST_DIR)
NDK_BIN       := $(NDK_TOOLCHAIN)$(PLATFORM_DIR)/bin
CLANG_RT_DIR = $(strip \
  $(shell \
    [ -n "$(ANDROID_NDK_ROOT)" ] && \
    "$(NDK_BIN)/clang" --print-runtime-dir \
      | xargs dirname | xargs dirname | xargs -I{} echo {}/linux \
  ) \
)


# Export to sub‐recipes
export PATH          := $(PATH):$(NDK_BIN)
export ANDROID_NDK_HOME := $(ANDROID_NDK_ROOT)
export NDK_HOME         := $(ANDROID_NDK_ROOT)
export CLANG_RT_DIR


# Tools
CARGO          := cargo
BUN            := bun
WASM_PACK      := wasm-pack
UNIFFI_BINDGEN := $(TARGET_DIR)/uniffi-bindgen

# Default goal
.DEFAULT_GOAL := local

# Directory we store timestamps in
STAMPS := .stamps
TOUCH_STAMP = @mkdir -p $(STAMPS) && touch $@

#-------------------------------------------------------------------------------
# Rust file-based heuristics
#-------------------------------------------------------------------------------

# Relevant crates for FFI builds
CRATES := crypto keystore crypto-macros mls-provider

# Workspace-level Cargo config
WORKSPACE_CARGO_FILES := Cargo.toml Cargo.lock

# Per-crate manifests
CRATE_MANIFESTS := $(addsuffix /Cargo.toml,$(CRATES))

# Enumerate all .rs files in relevant crates
RUST_RS_FILES := $(shell find $(CRATES) -type f -name '*.rs' 2>/dev/null)

# Complete dependency set for FFI-related Cargo builds
RUST_SOURCES := $(WORKSPACE_CARGO_FILES) $(CRATE_MANIFESTS) $(RUST_RS_FILES)

#-------------------------------------------------------------------------------
# Build FFI artifacts
#-------------------------------------------------------------------------------

# Build bindgen binary (independent of rust sources changing)
$(UNIFFI_BINDGEN):
	cargo build $(CARGO_BUILD_ARGS) \
		--locked \
		--features uniffi/cli \
		--package core-crypto-ffi \
		--bin uniffi-bindgen

# Build the FFI library
FFI_LIBRARY := $(TARGET_DIR)/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
$(FFI_LIBRARY): $(RUST_SOURCES)
	cargo build $(CARGO_BUILD_ARGS) \
		--locked \
		--package core-crypto-ffi \
		--lib

# Make aliases
.PHONY: uniffi-bindgen
uniffi-bindgen:  $(TARGET_DIR)/uniffi-bindgen

#-------------------------------------------------------------------------------
# Use stamp files for generators: only re-run when inputs change
#-------------------------------------------------------------------------------

# Swift bindings
ifneq ($(UNAME_S),Darwin)
$(STAMPS)/bindings-swift:
	$(warning Skipping build for "bindings-swift", as swift bindings generation is only supported on Darwin because OpenSSL can't be cross-compiled on non-Darwin systems; this is "$(UNAME_S)".)
else
$(STAMPS)/bindings-swift: $(UNIFFI_BINDGEN) $(FFI_LIBRARY)
	mkdir -p crypto-ffi/bindings/Swift/WireCoreCryptoUniffi/WireCoreCryptoUniffi
	$(UNIFFI_BINDGEN) generate \
	  --language swift \
	  --out-dir crypto-ffi/bindings/Swift/WireCoreCryptoUniffi/WireCoreCryptoUniffi \
	  --library $(FFI_LIBRARY)
	$(TOUCH_STAMP)
endif

.PHONY: bindings-swift swift
bindings-swift: $(STAMPS)/bindings-swift ## Generate Swift bindings
swift: $(STAMPS)/bindings-swift $(STAMPS)/docs-swift

# Kotlin-Android bindings
$(STAMPS)/bindings-kotlin-android: $(UNIFFI_BINDGEN) $(FFI_LIBRARY)
	mkdir -p crypto-ffi/bindings/android/src/main/uniffi
	$(UNIFFI_BINDGEN) generate \
	  --config uniffi-android.toml \
	  --language kotlin \
	  --no-format \
	  --out-dir crypto-ffi/bindings/android/src/main/uniffi \
	  --library $(FFI_LIBRARY)
	$(TOUCH_STAMP)

.PHONY: bindings-kotlin-android
bindings-kotlin-android: $(STAMPS)/bindings-kotlin-android ## Generate Kotlin bindings for Android

# Kotlin-JVM bindings
$(STAMPS)/bindings-kotlin-jvm: $(UNIFFI_BINDGEN) $(FFI_LIBRARY)
	mkdir -p crypto-ffi/bindings/jvm/src/main/uniffi
	$(UNIFFI_BINDGEN) generate \
	  --language kotlin \
	  --no-format \
	  --out-dir crypto-ffi/bindings/jvm/src/main/uniffi \
	  --library $(FFI_LIBRARY)
	$(TOUCH_STAMP)

.PHONY: bindings-kotlin-jvm
bindings-kotlin-jvm: $(STAMPS)/bindings-kotlin-jvm ## Generate Kotlin bindings for JVM

# Grouped Kotlin bindings
.PHONY: bindings-kotlin
bindings-kotlin: $(STAMPS)/bindings-kotlin-android $(STAMPS)/bindings-kotlin-jvm ## Generate all Kotlin bindings

#-------------------------------------------------------------------------------
# WASM build + JS deps via stamps
#-------------------------------------------------------------------------------

# The default build condition is `dev`, which is much faster.
WASM_BUILD_ARGS := $(if $(RELEASE),,--dev)

# Generate WASM package
$(STAMPS)/wasm-build: $(RUST_SOURCES)
	cd crypto-ffi && \
	$(WASM_PACK) build \
	  --locked \
	  --no-pack \
	  --out-dir bindings/js/src/autogenerated \
	  --out-name core-crypto-ffi \
	  --mode normal \
	  --target web \
	  $(WASM_BUILD_ARGS)
	$(TOUCH_STAMP)

.PHONY: wasm-build
wasm-build: $(STAMPS)/wasm-build

# Install JS deps with Bun
$(STAMPS)/bun-deps: $(PACKAGE_JSON)
	$(BUN) install --frozen-lockfile --cwd crypto-ffi/bindings/js
	$(TOUCH_STAMP)

.PHONY: bun-deps
bun-deps: $(STAMPS)/bun-deps ## Install JS dependencies using bun

# Full JS binding step
bindings-js: wasm-build $(JS_OUT) ## Generate JavaScript bindings

# All bindings
.PHONY: bindings
bindings: bindings-kotlin bindings-js $(if $(filter Darwin,$(UNAME_S)),bindings-swift) ## Generate all bindings

#-------------------------------------------------------------------------------
# Documentation targets
#-------------------------------------------------------------------------------

# Rust generic docs
$(STAMPS)/docs-rust-generic: $(RUST_SOURCES)
	$(CARGO) doc --no-deps
	$(TOUCH_STAMP)

.PHONY: docs-rust-generic
docs-rust-generic: $(STAMPS)/docs-rust-generic ## Generate Rust docs for the host platform's default target ("generic")

# Rust WASM docs
$(STAMPS)/docs-rust-wasm: $(RUST_SOURCES)
	$(CARGO) doc --no-deps --target=wasm32-unknown-unknown
	$(TOUCH_STAMP)

.PHONY: docs-rust-wasm
docs-rust-wasm: $(STAMPS)/docs-rust-wasm ## Generate Rust docs for wasm32-unknown-unknown

# Kotlin Dokka (Android) docs
$(STAMPS)/docs-kotlin: jvm
	cd crypto-ffi/bindings && ./gradlew android:dokkaGeneratePublicationHtml
	mkdir -p target/kotlin/doc
	cp -R crypto-ffi/bindings/android/build/dokka/html/ target/kotlin/doc
	$(TOUCH_STAMP)

.PHONY: docs-kotlin
docs-kotlin: $(STAMPS)/docs-kotlin ## Generate Kotlin docs

# TypeScript docs via Typedoc
$(STAMPS)/docs-ts: $(STAMPS)/wasm-build $(STAMPS)/bun-deps
	cd crypto-ffi/bindings/js && \
	$(BUN) x typedoc \
	  --basePath ./ \
	  --entryPoints src/CoreCrypto.ts \
	  --tsconfig tsconfig.json \
	  --out ../../target/typescript/doc \
	  --readme none \
	  --treatWarningsAsErrors
	$(TOUCH_STAMP)

.PHONY: docs-ts
docs-ts: $(STAMPS)/docs-ts ## Generate TypeScript docs

# Swift docs via Jazzy (macOS only)
$(STAMPS)/docs-swift: ios
	mkdir -p target/swift/doc
	cd crypto-ffi/bindings/Swift/WireCoreCrypto && \
	jazzy \
	  --modules WireCoreCrypto,WireCoreCryptoUniffi \
	  --build-tool-arguments -project,WireCoreCrypto.xcodeproj,-scheme,WireCoreCrypto,-configuration,$(XCODE_CONFIG) \
	  -o ../../../target/swift/doc
	$(TOUCH_STAMP)

.PHONY: docs-swift
docs-swift: $(STAMPS)/docs-swift ## Generate Swift iOS docs (macOS only)

# Group all docs
.PHONY: docs
docs: docs-rust-generic docs-rust-wasm docs-kotlin docs-ts $(if $(filter Darwin,$(UNAME_S)),docs-swift) ## Generate all docs (excluding Swift on non-Darwin platforms)

#-------------------------------------------------------------------------------
# iOS builds
#-------------------------------------------------------------------------------

$(STAMPS)/ios-device: $(STAMPS)/bindings-swift
	IPHONEOS_DEPLOYMENT_TARGET=16.0 \
	$(CARGO) rustc --locked \
	  --target aarch64-apple-ios \
	  --crate-type=cdylib \
	  --crate-type=staticlib \
	  --package core-crypto-ffi \
	  $(CARGO_BUILD_ARGS) -- -C strip=symbols
	$(TOUCH_STAMP)

.PHONY: ios-device
ios-device: $(STAMPS)/ios-device ## Build core-crypto-ffi for aarch64-apple-ios for iOS 16.0 (macOS only)

$(STAMPS)/ios-simulator-arm: $(STAMPS)/bindings-swift
	CRATE_CC_NO_DEFAULTS=1 \
	TARGET_CFLAGS="--target=arm64-apple-ios14.0.0-simulator \
	-mios-simulator-version-min=14.0 \
	-isysroot $$(xcrun --show-sdk-path --sdk iphonesimulator)" \
	$(CARGO) rustc --locked \
	  --target aarch64-apple-ios-sim \
	  --crate-type=cdylib \
	  --crate-type=staticlib \
	  --package core-crypto-ffi \
	  $(CARGO_BUILD_ARGS) -- -C strip=symbols
	$(TOUCH_STAMP)

.PHONY: ios-simulator-arm
ios-simulator-arm: $(STAMPS)/ios-simulator-arm ## Build core-crypto-ffi for aarch64-apple-ios-sim, iOS 14.0.0 (macOS only)
$(STAMPS)/ios: $(STAMPS)/ios-device $(STAMPS)/ios-simulator-arm
	$(TOUCH_STAMP)

.PHONY: ios
ios: $(STAMPS)/ios

# Build XCFramework (macOS only)
$(STAMPS)/ios-create-xcframework: ios
	cd crypto-ffi/bindings/swift && ./build-xcframework.sh
	$(TOUCH_STAMP)

.PHONY: ios-create-xcframework
ios-create-xcframework: $(STAMPS)/ios-create-xcframework ## Build the XCode framework (macOS only)

#-------------------------------------------------------------------------------
# Android builds
#-------------------------------------------------------------------------------

# Check NDK env
.PHONY: android-env
android-env:
	@if [ -z "$(ANDROID_NDK_HOME)" -a -z "$(NDK_HOME)" ]; then \
	  echo "ERROR: set ANDROID_NDK_HOME or NDK_HOME"; exit 1; \
	fi
	@echo "NDK configured at $(ANDROID_NDK_ROOT)"
	@echo "  toolchain: $(NDK_TOOLCHAIN)"
	@echo "  clang-rt:  $(CLANG_RT_DIR)"


target/armv7-linux-androideabi/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION): android-env
	$(CARGO) rustc --locked \
	  --target armv7-linux-androideabi \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- -C strip=symbols
	$(TOUCH_STAMP)

.PHONY: android-armv7
android-armv7: target/armv7-linux-androideabi/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION) ## Build core-crypto-ffi for armv7-linux-androideabi

target/aarch64-linux-android/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION): android-env
	$(CARGO) rustc --locked \
	  --target aarch64-linux-android \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- -C strip=symbols
	$(TOUCH_STAMP)

.PHONY: android-armv8
android-armv8: target/aarch64-linux-android/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION) ## Build core-crypto-ffi for aarch64-linux-android

target/x86_64-linux-android/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION): android-env
	# Link clang_rt.builtins statically for x86_64 Android
	$(CARGO) rustc --locked \
	  --target x86_64-linux-android \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- \
	  -C strip=symbols \
	  -l static=clang_rt.builtins-x86_64-android \
	  -L $$(dirname $$($(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(PLATFORM_DIR)/bin/clang --print-runtime-dir))/linux
	$(TOUCH_STAMP)

.PHONY: android-x86
android-x86: target/x86_64-linux-android/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION) ## Build core-crypto-ffi for x86_64-linux-android

.PHONY: android-all
android-all: android-armv7 android-armv8 android-x86 ## Build core-crypto-ffi for all Android targets

.PHONY: android-test
android-test: android-all $(STAMPS)/bindings-kotlin-android ## Run Kotlin tests on Android
	cd crypto-ffi/bindings && \
	./gradlew android:build -x lint -x lintRelease

#-------------------------------------------------------------------------------
# JVM native builds (Darwin + Linux)
#-------------------------------------------------------------------------------

# darwin build
$(STAMPS)/jvm-darwin: $(STAMPS)/bindings-kotlin-jvm
	cd crypto-ffi && \
	$(CARGO) rustc --locked \
	  --target aarch64-apple-darwin \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- -C strip=symbols
	$(TOUCH_STAMP)

.PHONY: jvm-darwin
jvm-darwin: $(STAMPS)/jvm-darwin ## Build core-crypto-ffi for JVM on aarch64-apple-darwin

# linux build
$(STAMPS)/jvm-linux: $(STAMPS)/bindings-kotlin-jvm
	cd crypto-ffi && \
	$(CARGO) rustc --locked \
	  --target x86_64-unknown-linux-gnu \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- -C strip=symbols
	$(TOUCH_STAMP)

.PHONY: jvm-linux
jvm-linux: $(STAMPS)/jvm-linux ## Build core-crypto-ffi for JVM on x86_64-unknown-linux-gnu

.PHONY: jvm
ifeq ($(UNAME_S),Linux)
jvm: jvm-linux ## Build core-crypto-ffi for JVM (automatically select the target based on the host machine)
else ifeq ($(UNAME_S),Darwin)
jvm: jvm-darwin
else
$(error Unsupported host platform for jvm: $(UNAME_S))
endif

.PHONY: jvm-test
jvm-test: ## Run Kotlin tests on JVM (assuming you ran `make jvm` at some earlier time)
	cd crypto-ffi/bindings && \
	./gradlew jvm:build -x lint -x lintRelease


#-------------------------------------------------------------------------------
# Aggregate targets
#-------------------------------------------------------------------------------

.PHONY: wasm local all
wasm: bindings-js  ## Alias for bindings-js
local: bindings ts-fmt ## Generate and format all bindings
all: android wasm jvm $(if $(filter Darwin,$(UNAME_S)),ios) docs ## Generate bindings for all platforms (android, iOS, wasm) and generate docs

#-------------------------------------------------------------------------------
# TypeScript / JS tasks (from crypto-ffi/bindings/js/package.json)
#-------------------------------------------------------------------------------

JS_DIR := crypto-ffi/bindings/js
JS_SRC_DIR   := $(JS_DIR)/src
PACKAGE_JSON := $(JS_DIR)/package.json

GEN_DIR := $(JS_SRC_DIR)/autogenerated
JS_GEN := $(GEN_DIR)/core-crypto-ffi.js
WASM_GEN := $(GEN_DIR)/core-crypto-ffi_bg.wasm

# find all .ts source files under src/ except in src/autogenerated
TS_SRCS   := $(shell ls $(JS_SRC_DIR)/*.ts | grep -v corecrypto.d.ts)

JS_OUT := $(JS_DIR)/src/corecrypto.js
DTS_OUT := $(JS_DIR)/src/corecrypto.d.ts


# always remove old outputs
.PHONY: ts-clean
ts-clean: ## Cleanup old TypeScript build outputs
	@rm -f $(JS_OUT) $(DTS_OUT) \
	&& rm -rf $(GEN_DIR)

$(STAMPS)/ts-fmt: $(TS_SRCS)
	cd $(JS_DIR) && bun eslint --max-warnings=0 --fix
	$(TOUCH_STAMP)

.PHONY: ts-fmt
ts-fmt: $(STAMPS)/ts-fmt ## Format TypeScript files via eslint

$(JS_GEN): wasm-build
$(WASM_GEN): wasm-build

# build corecrypto.js
$(JS_OUT): ts-clean $(STAMPS)/bun-deps $(JS_GEN) $(WASM_GEN) $(TS_SRCS) $(PACKAGE_JSON)
	cd $(JS_DIR) && \
	bun build \
	  --target browser \
	  --format esm \
	  --outfile src/corecrypto.js \
	  src/CoreCrypto.ts
	$(TOUCH_STAMP)

.PHONY: ts-build
ts-build: $(JS_OUT)

# generate TypeScript defs only when corecrypto.js changed
$(DTS_OUT): $(JS_OUT) $(TS_SRCS)
	cd $(JS_DIR) && \
	bun x dts-bundle-generator \
	  --project tsconfig.json \
	  -o src/corecrypto.d.ts \
	  --no-check \
	  --export-referenced-types false \
	  src/CoreCrypto.ts
	@touch $@

.PHONY: ts
ts: $(DTS_OUT) ## Build the TypeScript wrapper

# run WebDriver tests + bun’s built-in tests
.PHONY: ts-test
ts-test: ## Run TypeScript wrapper tests via wdio and bun (assuming you ran `make ts` at some earlier time)
	cd $(JS_DIR) && \
	bun x wdio run wdio.conf.ts --spec test/wdio/*.test.ts && \
	bun test

# run WebDriver benches
.PHONY: ts-bench
ts-bench: ts ## Run TypeScript wrapper benches in Chrome via wdio
	cd $(JS_DIR) && \
	bun x wdio run wdio.conf.ts --spec benches/**/*.bench.ts --log-level warn

.PHONY: clean
clean: ts-clean ## Run cargo clean and the ts-clean target, remove all stamps
	cargo clean && \
	rm -r $(STAMPS)
