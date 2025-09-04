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
  GRADLE_BUILD_TYPE := Debug
  RELEASE_MODE := debug
else
  CARGO_BUILD_ARGS := --release
  XCODE_CONFIG := Release
  GRADLE_BUILD_TYPE := Release
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

# Default goal
.DEFAULT_GOAL := local

# Directory we store timestamps in
STAMPS := .stamps

# We're writing a timestamp into the file because CI relies on file hashes to
# change when the stamp files are updated.
TOUCH_STAMP = @mkdir -p $(STAMPS) && echo "$$(date)" > $@

#-------------------------------------------------------------------------------
# Rust file-based heuristics
#-------------------------------------------------------------------------------

# Relevant crates for FFI builds
CRATES := crypto crypto-ffi keystore crypto-macros mls-provider

# Workspace-level Cargo config
WORKSPACE_CARGO_FILES := Cargo.toml Cargo.lock

# Per-crate manifests
CRATE_MANIFESTS := $(addsuffix /Cargo.toml,$(CRATES))

# Enumerate all .rs files in relevant crates
RUST_RS_FILES := $(shell find $(CRATES) -type f -name '*.rs' 2>/dev/null | LC_ALL=C sort)

# Complete dependency set for FFI-related Cargo builds
RUST_SOURCES := $(WORKSPACE_CARGO_FILES) $(CRATE_MANIFESTS) $(RUST_RS_FILES)

# Used by CI to calculate a hash of prerequisite files of a make rule
%-hash-deps:
	@deps="$($*-deps)"; \
	hash=$$(sha256sum $$deps | sha256sum | awk '{print $$1}'); \
	echo "$$hash"

#-------------------------------------------------------------------------------
# Build FFI artifacts
#-------------------------------------------------------------------------------

# Build bindgen binary (independent of rust sources changing)
#
# We need to build this binary if it does not exist, or if the uniffi version
# has changed (see https://github.com/mozilla/uniffi-rs/issues/2622).
GET_UNIFFI_VERSION = cargo metadata --format-version 1 | jq -r '.packages[] | select(.name == "uniffi") | .version'
UNIFFI_VERSION_FILE := $(STAMPS)/uniffi-version

# Version file: only rewrite if version changed
$(UNIFFI_VERSION_FILE): Cargo.lock
	current_version="$$( $(GET_UNIFFI_VERSION) )"; \
	if [ ! -f $@ ] || [ "$$(cat $@)" != "$$current_version" ]; then \
		mkdir -p .stamps; \
	    echo "$$current_version" > $@; \
	fi


UNIFFI_BINDGEN := $(TARGET_DIR)/uniffi-bindgen
uniffi-bindgen-deps := $(UNIFFI_VERSION_FILE)
$(UNIFFI_BINDGEN): $(uniffi-bindgen-deps)
	cargo build $(CARGO_BUILD_ARGS) \
		--locked \
		--features uniffi/cli \
		--bin uniffi-bindgen

# Build the FFI library
FFI_LIBRARY := $(TARGET_DIR)/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
ffi-library-deps := $(RUST_SOURCES)
$(FFI_LIBRARY): $(ffi-library-deps)
	cargo build $(CARGO_BUILD_ARGS) \
		--locked \
		--package core-crypto-ffi \
		--lib

# Make aliases
.PHONY: uniffi-bindgen ffi-library
uniffi-bindgen: $(UNIFFI_BINDGEN)  ## Build the uniffi bindgen binary
ffi-library: $(FFI_LIBRARY) ## Build the libcore_crypto_ffi library

#-------------------------------------------------------------------------------
# Use stamp files for generators: only re-run when inputs change
#-------------------------------------------------------------------------------

bindings-deps := $(UNIFFI_BINDGEN) $(FFI_LIBRARY)

# Swift bindings
UNIFFI_SWIFT_OUTPUT := crypto-ffi/bindings/swift/WireCoreCryptoUniffi/WireCoreCryptoUniffi/core_crypto_ffi.swift
bindings-swift-deps := $(bindings-deps)

ifneq ($(UNAME_S),Darwin)
$(UNIFFI_SWIFT_OUTPUT):
	$(warning Skipping build for "bindings-swift", as swift bindings generation is only supported on \
	          Darwin because OpenSSL can't be cross-compiled on non-Darwin systems; this is "$(UNAME_S)".)
else
$(UNIFFI_SWIFT_OUTPUT): $(bindings-swift-deps)
	mkdir -p crypto-ffi/bindings/swift/WireCoreCryptoUniffi/WireCoreCryptoUniffi
	$(UNIFFI_BINDGEN) generate \
	  --config crypto-ffi/uniffi.toml \
	  --language swift \
	  --out-dir crypto-ffi/bindings/swift/WireCoreCryptoUniffi/WireCoreCryptoUniffi \
	  --library $(FFI_LIBRARY)
endif

.PHONY: bindings-swift swift
bindings-swift: $(UNIFFI_SWIFT_OUTPUT) ## Generate Swift bindings

swift: bindings-swift $(STAMPS)/docs-swift

# Kotlin-Android bindings
UNIFFI_ANDROID_OUTPUT := crypto-ffi/bindings/android/src/main/uniffi/com/wire/crypto/core_crypto_ffi.kt
bindings-kotlin-android-deps := $(bindings-deps)

$(UNIFFI_ANDROID_OUTPUT): $(bindings-kotlin-android-deps)
	mkdir -p crypto-ffi/bindings/android/src/main/uniffi
	$(UNIFFI_BINDGEN) generate \
	  --config crypto-ffi/uniffi-android.toml \
	  --language kotlin \
	  --no-format \
	  --out-dir crypto-ffi/bindings/android/src/main/uniffi \
	  --library $(FFI_LIBRARY)

.PHONY: bindings-kotlin-android
bindings-kotlin-android: $(UNIFFI_ANDROID_OUTPUT)  ## Generate Kotlin bindings for Android

# Kotlin-JVM bindings
UNIFFI_JVM_OUTPUT := crypto-ffi/bindings/jvm/src/main/uniffi/com/wire/crypto/core_crypto_ffi.kt
bindings-kotlin-jvm-deps := $(bindings-deps)

$(UNIFFI_JVM_OUTPUT): $(bindings-kotlin-jvm-deps)
	mkdir -p crypto-ffi/bindings/jvm/src/main/uniffi
	$(UNIFFI_BINDGEN) generate \
	  --config crypto-ffi/uniffi.toml \
	  --language kotlin \
	  --no-format \
	  --out-dir crypto-ffi/bindings/jvm/src/main/uniffi \
	  --library $(FFI_LIBRARY)

.PHONY: bindings-kotlin-jvm
bindings-kotlin-jvm: $(UNIFFI_JVM_OUTPUT) ## Generate Kotlin bindings for JVM

# Grouped Kotlin bindings
.PHONY: bindings-kotlin
bindings-kotlin: bindings-kotlin-android bindings-kotlin-jvm ## Generate all Kotlin bindings

#-------------------------------------------------------------------------------
# iOS builds
#-------------------------------------------------------------------------------

ios-device-deps := $(RUST_SOURCES)
$(STAMPS)/ios-device: $(ios-device-deps)
	IPHONEOS_DEPLOYMENT_TARGET=16.0 \
	cargo rustc --locked \
	  --target aarch64-apple-ios \
	  --crate-type=cdylib \
	  --crate-type=staticlib \
	  --package core-crypto-ffi \
	  $(CARGO_BUILD_ARGS) -- -C strip=symbols
	$(TOUCH_STAMP)

.PHONY: ios-device
ios-device: $(STAMPS)/ios-device ## Build core-crypto-ffi for aarch64-apple-ios for iOS 16.0 (macOS only)

ios-simulator-arm-deps := $(RUST_SOURCES)
$(STAMPS)/ios-simulator-arm: $(ios-simulator-arm-deps)
	CRATE_CC_NO_DEFAULTS=1 \
	TARGET_CFLAGS="--target=arm64-apple-ios14.0.0-simulator \
	-mios-simulator-version-min=14.0 \
	-isysroot $$(xcrun --show-sdk-path --sdk iphonesimulator)" \
	cargo rustc --locked \
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

ios-create-xcframework-deps := $(STAMPS)/ios $(STAMPS)/bindings-swift
$(STAMPS)/ios-create-xcframework: $(ios-create-xcframework-deps)
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

ANDROID_ARMv7 := target/armv7-linux-androideabi/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
android-armv7-deps := $(RUST_SOURCES)
$(ANDROID_ARMv7): $(android-armv7-deps) | android-env
	cargo rustc --locked \
	  --target armv7-linux-androideabi \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- -C strip=symbols

.PHONY: android-armv7
android-armv7: $(ANDROID_ARMv7) ## Build core-crypto-ffi for armv7-linux-androideabi

ANDROID_ARMv8 := target/aarch64-linux-android/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
android-armv8-deps := $(RUST_SOURCES)
$(ANDROID_ARMv8): $(android-armv8-deps) | android-env
	cargo rustc --locked \
	  --target aarch64-linux-android \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- -C strip=symbols

.PHONY: android-armv8
android-armv8: $(ANDROID_ARMv8) ## Build core-crypto-ffi for aarch64-linux-android

ANDROID_X86 := target/x86_64-linux-android/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
android-x86-deps := $(RUST_SOURCES)
$(ANDROID_X86): $(android-x86-deps) | android-env
	# Link clang_rt.builtins statically for x86_64 Android
	cargo rustc --locked \
	  --target x86_64-linux-android \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- \
	  -C strip=symbols \
	  -l static=clang_rt.builtins-x86_64-android \
	  -L $$(dirname $$($(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(PLATFORM_DIR)/bin/clang --print-runtime-dir))/linux

.PHONY: android-x86
android-x86: $(ANDROID_X86) ## Build core-crypto-ffi for x86_64-linux-android

.PHONY: android
android-deps := $(ANDROID_ARMv7) $(ANDROID_ARMv8) $(ANDROID_X86) $(UNIFFI_ANDROID_OUTPUT)
android: $(android-deps) ## Build all Android targets
	cd crypto-ffi/bindings && \
	./gradlew android:assemble$(GRADLE_BUILD_TYPE)

#-------------------------------------------------------------------------------
# JVM native builds (Darwin + Linux)
#-------------------------------------------------------------------------------

# darwin build
JVM_DARWIN_LIB := target/aarch64-apple-darwin/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
jvm-darwin-deps := $(RUST_SOURCES)
$(JVM_DARWIN_LIB): $(jvm-darwin-deps)
	cd crypto-ffi && \
	cargo rustc --locked \
	  --target aarch64-apple-darwin \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- -C strip=symbols

.PHONY: jvm-darwin
jvm-darwin: $(JVM_DARWIN_LIB) ## Build core-crypto-ffi for JVM on aarch64-apple-darwin

# linux build
JVM_LINUX_LIB := target/x86_64-unknown-linux-gnu/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
jvm-linux-deps := $(RUST_SOURCES)
$(JVM_LINUX_LIB): $(jvm-linux-deps)
	cd crypto-ffi && \
	cargo rustc --locked \
	  --target x86_64-unknown-linux-gnu \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- -C strip=symbols

.PHONY: jvm-linux
jvm-linux: $(JVM_LINUX_LIB) ## Build core-crypto-ffi for JVM on x86_64-unknown-linux-gnu

.PHONY: jvm
ifeq ($(UNAME_S),Linux)
JVM_LIB := $(JVM_LINUX_LIB)
jvm: jvm-linux ## Build core-crypto-ffi for JVM (automatically select the target based on the host machine)
else ifeq ($(UNAME_S),Darwin)
JVM_LIB := $(JVM_DARWIN_LIB)
jvm: jvm-darwin
else
$(error Unsupported host platform for jvm: $(UNAME_S))
endif

.PHONY: jvm-test
jvm-test: $(JVM_LIB) bindings-kotlin-jvm ## Run Kotlin tests on JVM
	cd crypto-ffi/bindings && \
	./gradlew jvm:test --rerun

#-------------------------------------------------------------------------------
# TypeScript / JS tasks
#-------------------------------------------------------------------------------

JS_DIR := crypto-ffi/bindings/js
JS_SRC_DIR   := $(JS_DIR)/src
PACKAGE_JSON := $(JS_DIR)/package.json
BUN_LOCK := $(JS_DIR)/bun.lock
BUNFIG := $(JS_DIR)/bunfig.toml

GEN_DIR := $(JS_SRC_DIR)/autogenerated
JS_GEN := $(GEN_DIR)/core-crypto-ffi.js
WASM_GEN := $(GEN_DIR)/core-crypto-ffi_bg.wasm

# find all .ts source files under src/ except `*.d.ts`
TS_SRCS := $(shell find $(JS_SRC_DIR) -type f -name '*.ts' -not -name '*.d.ts' 2>/dev/null | LC_ALL=C sort)

JS_OUT := $(JS_DIR)/src/corecrypto.js
DTS_OUT := $(JS_DIR)/src/corecrypto.d.ts

# The default build condition is `dev`, which is much faster.
WASM_BUILD_ARGS := $(if $(RELEASE),,--dev)
# In release mode, fail if the lockfile does not match
BUN_FROZEN_LOCKFILE := $(if $(RELEASE),--frozen-lockfile)

# Generate WASM
wasm-build-deps := $(RUST_SOURCES)
# Note the `&:` syntax: that's a "grouped target" rule: https://www.gnu.org/software/make/manual/html_node/Multiple-Targets.html
$(JS_GEN) $(WASM_GEN) &: $(wasm-build-deps)
	cd crypto-ffi && \
	wasm-pack build \
	  --locked \
	  --no-pack \
	  --out-dir bindings/js/src/autogenerated \
	  --out-name core-crypto-ffi \
	  --mode normal \
	  --target web \
	  $(WASM_BUILD_ARGS)

.PHONY: wasm-build
wasm-build: $(WASM_GEN)

# Install JS deps with Bun
# We want the `node_modules` directory to exist, and we want never to manually create it,
# and we want to ensure that this runs if the directory does not exist. So:
NODE_MODULES := $(JS_DIR)/node_modules/.stamp
$(BUN_LOCK) $(NODE_MODULES) &: $(PACKAGE_JSON)
	bun install $(BUN_FROZEN_LOCKFILE) --cwd $(JS_DIR)
# if the lockfile is unchanged, bun reports "no changes" and does not update the lock file
# which would be fine, bun is fast, except that every step thereafter is dirty
# so we update the mtime manually here
	@touch $(BUN_LOCK)
# also ensure the `NODE_MODULES` stamp file exists / is current
	@touch $(NODE_MODULES)

.PHONY: bun-deps
bun-deps: $(BUN_LOCK) ## Install JS dependencies using bun

# always remove old outputs
.PHONY: ts-clean
ts-clean: ## Cleanup old TypeScript build outputs
	@rm -f $(JS_OUT) $(DTS_OUT) \
	&& rm -rf $(GEN_DIR)

# build corecrypto.js
js-deps := $(BUN_LOCK) $(NODE_MODULES) $(JS_GEN) $(WASM_GEN) $(TS_SRCS) $(PACKAGE_JSON) $(BUNFIG)
$(JS_OUT): $(js-deps)
# clean the output files before building; otherwise `bun` appends instead of replacing
# we do _not_ want to rm `$(GEN_DIR); that kills our generated wasm code
	rm -f $(JS_OUT) $(DTS_OUT)
	cd $(JS_DIR) && \
	bun build \
	  --target browser \
	  --format esm \
	  --outfile src/corecrypto.js \
	  src/CoreCrypto.ts

.PHONY: js
js: $(JS_OUT)

# generate TypeScript defs only when corecrypto.js changed
ts-deps := $(JS_OUT)
$(DTS_OUT): $(ts-deps)
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

$(STAMPS)/ts-fmt: $(TS_SRCS)
	cd $(JS_DIR) && bun eslint --max-warnings=0 --fix
	$(TOUCH_STAMP)

.PHONY: ts-fmt
ts-fmt: $(STAMPS)/ts-fmt ## Format TypeScript files via eslint

# run WebDriver tests + bun’s built-in tests
.PHONY: ts-test
ts-test: $(DTS_OUT) ## Run TypeScript wrapper tests via wdio and bun
	cd $(JS_DIR) && \
	bun x wdio run wdio.conf.ts --spec test/wdio/*.test.ts && \
	bun test

# run WebDriver benches
.PHONY: ts-bench
ts-bench: $(DTS_OUT) ## Run TypeScript wrapper benches in Chrome via wdio
	cd $(JS_DIR) && \
	bun x wdio run wdio.conf.ts --spec benches/**/*.bench.ts --log-level warn

#-------------------------------------------------------------------------------
# Documentation targets
#-------------------------------------------------------------------------------

# Rust generic docs
$(STAMPS)/docs-rust-generic: $(RUST_SOURCES)
	cargo doc --no-deps
	$(TOUCH_STAMP)

.PHONY: docs-rust-generic
docs-rust-generic: $(STAMPS)/docs-rust-generic ## Generate Rust docs for the host platform's default target ("generic")

# Rust WASM docs
$(STAMPS)/docs-rust-wasm: $(RUST_SOURCES)
	cargo doc --no-deps --target=wasm32-unknown-unknown
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
$(STAMPS)/docs-ts: $(DTS_OUT)
	cd crypto-ffi/bindings/js && \
	bun x typedoc \
	  --basePath ./ \
	  --entryPoints src/CoreCrypto.ts \
	  --tsconfig tsconfig.json \
	  --out ../../../target/typescript/doc \
	  --readme none \
	  --treatWarningsAsErrors
	$(TOUCH_STAMP)

.PHONY: docs-ts
docs-ts: $(STAMPS)/docs-ts ## Generate TypeScript docs

# Swift docs via Jazzy (macOS only)
docs-swift-deps := $(STAMPS)/ios $(STAMPS)/bindings-swift
$(STAMPS)/docs-swift: $(docs-swift-deps)
	mkdir -p target/swift/doc
	cd crypto-ffi/bindings/swift/WireCoreCrypto && \
	jazzy \
	  --modules WireCoreCrypto,WireCoreCryptoUniffi \
	  --build-tool-arguments -project,WireCoreCrypto.xcodeproj,-scheme,WireCoreCrypto,-configuration,$(XCODE_CONFIG) \
	  -o ../../../../target/swift/doc
	$(TOUCH_STAMP)

.PHONY: docs-swift
docs-swift: $(STAMPS)/docs-swift ## Generate Swift iOS docs (macOS only)

# Group all docs
.PHONY: docs
docs: docs-rust-generic docs-rust-wasm docs-kotlin docs-ts $(if $(filter Darwin,$(UNAME_S)),docs-swift) ## Generate all docs (excluding Swift on non-Darwin platforms)

#-------------------------------------------------------------------------------
# Aggregate targets
#-------------------------------------------------------------------------------

.PHONY: wasm bindings local all clean
wasm: ts  ## Alias for ts
bindings: bindings-kotlin ts $(if $(filter Darwin,$(UNAME_S)),bindings-swift) ## Generate all bindings
local: bindings ts-fmt ## Generate and format all bindings
all: android wasm jvm $(if $(filter Darwin,$(UNAME_S)),ios) docs ## Generate bindings for all platforms (android, iOS, wasm) and generate docs
clean: ts-clean ## Run cargo clean and the ts-clean target, remove all stamps
	cargo clean
	rm -rf $(STAMPS)
