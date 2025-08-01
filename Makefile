# Makefile: Always run Cargo steps, but only re-run downstream generators when inputs change

SHELL := /usr/bin/env bash

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
UNIFFI_BINDGEN := target/release/uniffi-bindgen

# Default goal
.DEFAULT_GOAL := all

#-------------------------------------------------------------------------------
# 1) Dummy force target: always out-of-date, so Cargo build commands run every time
#-------------------------------------------------------------------------------
.PHONY: FORCE
FORCE:

#-------------------------------------------------------------------------------
# 2) Build artifacts via Cargo (always run Cargo; Cargo itself detects up-to-date)
#-------------------------------------------------------------------------------

# one rule to build both the FFI library and the bindgen binary
target/release/uniffi-bindgen: FORCE
	cargo build --release \
		--locked \
		--features uniffi/cli \
		--package core-crypto-ffi \
		--bin uniffi-bindgen

target/release/libcore_crypto_ffi.$(LIBRARY_EXTENSION): FORCE
	cargo build --release \
		--locked \
		--package core-crypto-ffi \
		--lib

# Make aliases
.PHONY: uniffi-bindgen release-build
uniffi-bindgen:  target/release/uniffi-bindgen
release-build:   target/release/libcore_crypto_ffi.$(LIBRARY_EXTENSION)

#-------------------------------------------------------------------------------
# 3) Use stamp files for generators: only re-run when inputs change
#-------------------------------------------------------------------------------

# Swift bindings
bindings-swift.stamp: target/release/uniffi-bindgen target/release/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
	mkdir -p crypto-ffi/bindings/Swift/WireCoreCryptoUniffi/WireCoreCryptoUniffi
	$(UNIFFI_BINDGEN) generate \
	  --language swift \
	  --out-dir crypto-ffi/bindings/Swift/WireCoreCryptoUniffi/WireCoreCryptoUniffi \
	  --library target/release/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
	touch $@

.PHONY: bindings-swift swift
bindings-swift: bindings-swift.stamp
swift: bindings-swift.stamp docs-swift.stamp

# Kotlin-Android bindings
bindings-kotlin-android.stamp: target/release/uniffi-bindgen target/release/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
	mkdir -p crypto-ffi/bindings/android/src/main/uniffi
	$(UNIFFI_BINDGEN) generate \
	  --config uniffi-android.toml \
	  --language kotlin \
	  --no-format \
	  --out-dir crypto-ffi/bindings/android/src/main/uniffi \
	  --library target/release/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
	touch $@

.PHONY: bindings-kotlin-android
bindings-kotlin-android: bindings-kotlin-android.stamp

# Kotlin-JVM bindings
bindings-kotlin-jvm.stamp: target/release/uniffi-bindgen target/release/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
	mkdir -p crypto-ffi/bindings/jvm/src/main/uniffi
	$(UNIFFI_BINDGEN) generate \
	  --language kotlin \
	  --no-format \
	  --out-dir crypto-ffi/bindings/jvm/src/main/uniffi \
	  --library target/release/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
	touch $@

.PHONY: bindings-kotlin-jvm
bindings-kotlin-jvm: bindings-kotlin-jvm.stamp

# Grouped Kotlin bindings
.PHONY: bindings-kotlin
bindings-kotlin: bindings-kotlin-android bindings-kotlin-jvm

#-------------------------------------------------------------------------------
# 4) WASM build + JS deps via stamps
#-------------------------------------------------------------------------------

# The default build condition is `dev`, which is much faster.
# To enable optimizations, set the `WASM_RELEASE` variable to any non-empty value:
#
# i.e.
#
#   make wasm WASM_RELEASE=1
WASM_BUILD_ARGS := $(if $(WASM_RELEASE),,--dev)

# Generate WASM package
wasm-build.stamp: FORCE
	cd crypto-ffi && \
	$(WASM_PACK) build \
	  --locked \
	  --no-pack \
	  --out-dir bindings/js/src/autogenerated \
	  --out-name core-crypto-ffi \
	  --mode normal \
	  --target web \
	  $(WASM_BUILD_ARGS)
	touch $@

.PHONY: wasm-build
wasm-build: wasm-build.stamp

# Install JS deps with Bun
bun-deps.stamp: $(PACKAGE_JSON)
	$(BUN) install --frozen-lockfile --cwd crypto-ffi/bindings/js
	touch $@

.PHONY: bun-deps
bun-deps: bun-deps.stamp

# Full JS binding step
bindings-js: wasm-build $(JS_OUT)

# All bindings
.PHONY: bindings
bindings: bindings-swift bindings-kotlin bindings-js

#-------------------------------------------------------------------------------
# 5) Documentation targets (stamp-based if desired)
#-------------------------------------------------------------------------------

# Rust generic docs
docs-rust-generic.stamp: FORCE
	$(CARGO) doc --no-deps
	touch $@

.PHONY: docs-rust-generic
docs-rust-generic: docs-rust-generic.stamp

# Rust WASM docs
docs-rust-wasm.stamp: FORCE
	$(CARGO) doc --no-deps --target=wasm32-unknown-unknown
	touch $@

.PHONY: docs-rust-wasm
docs-rust-wasm: docs-rust-wasm.stamp

# Kotlin Dokka (Android) docs
docs-kotlin.stamp: jvm
	cd crypto-ffi/bindings && ./gradlew android:dokkaGeneratePublicationHtml
	mkdir -p target/kotlin/doc
	cp -R crypto-ffi/bindings/android/build/dokka/html/ target/kotlin/doc
	touch $@

.PHONY: docs-kotlin
docs-kotlin: docs-kotlin.stamp

# TypeScript docs via Typedoc
docs-ts.stamp: wasm-build.stamp bun-deps.stamp
	cd crypto-ffi/bindings/js && \
	$(BUN) x typedoc \
	  --basePath ./ \
	  --entryPoints src/CoreCrypto.ts \
	  --tsconfig tsconfig.json \
	  --out ../../target/typescript/doc \
	  --readme none \
	  --treatWarningsAsErrors
	touch $@

.PHONY: docs-ts
docs-ts: docs-ts.stamp

# Swift docs via Jazzy (macOS only)
docs-swift.stamp:
	mkdir -p target/swift/doc
	cd crypto-ffi/bindings/Swift/WireCoreCrypto && \
	jazzy \
	  --modules WireCoreCrypto,WireCoreCryptoUniffi \
	  --build-tool-arguments "-project WireCoreCrypto.xcodeproj -scheme WireCoreCrypto" \
	  -o ../../../target/swift/doc
	touch $@

.PHONY: docs-swift
docs-swift: docs-swift.stamp

# Group all docs
.PHONY: docs
docs: docs-rust-generic docs-rust-wasm docs-kotlin docs-ts docs-swift

#-------------------------------------------------------------------------------
# 6) iOS builds (create stamp per sub‐target)
#-------------------------------------------------------------------------------

ios-device.stamp: bindings-swift.stamp
	IPHONEOS_DEPLOYMENT_TARGET=16.0 \
	$(CARGO) rustc --locked \
	  --target aarch64-apple-ios \
	  --crate-type=cdylib \
	  --crate-type=staticlib \
	  --package core-crypto-ffi \
	  --release -- -C strip=symbols
	touch $@

.PHONY: ios-device
ios-device: ios-device.stamp

ios-simulator-arm.stamp: bindings-swift.stamp
	CRATE_CC_NO_DEFAULTS=1 \
	TARGET_CFLAGS="--target=arm64-apple-ios14.0.0-simulator \
	-mios-simulator-version-min=14.0 \
	-isysroot $$(xcrun --show-sdk-path --sdk iphonesimulator)" \
	$(CARGO) rustc --locked \
	  --target aarch64-apple-ios-sim \
	  --crate-type=cdylib \
	  --crate-type=staticlib \
	  --package core-crypto-ffi \
	  --release -- -C strip=symbols
	touch $@

.PHONY: ios-simulator-arm
ios-simulator-arm: ios-simulator-arm.stamp

ios.stamp: ios-device.stamp ios-simulator-arm.stamp
	touch $@

.PHONY: ios
ios: ios.stamp

# Build XCFramework (macOS only)
ios-create-xcframework.stamp: ios.stamp
	cd crypto-ffi/bindings/swift && ./build-xcframework.sh
	touch $@

.PHONY: ios-create-xcframework
ios-create-xcframework: ios-create-xcframework.stamp

#-------------------------------------------------------------------------------
# 7) Android builds (stamp per architecture)
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


android-armv7.stamp: android-env
	$(CARGO) rustc --locked \
	  --target armv7-linux-androideabi \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  --release -- -C strip=symbols
	touch $@

.PHONY: android-armv7
android-armv7: android-armv7.stamp

android-armv8.stamp: android-env
	$(CARGO) rustc --locked \
	  --target aarch64-linux-android \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  --release -- -C strip=symbols
	touch $@

.PHONY: android-armv8
android-armv8: android-armv8.stamp

android-x86.stamp: android-env
	# Link clang_rt.builtins statically for x86_64 Android
	$(CARGO) rustc --locked \
	  --target x86_64-linux-android \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  --release -- \
	  -C strip=symbols \
	  -l static=clang_rt.builtins-x86_64-android \
	  -L $$(dirname $$($(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(PLATFORM_DIR)/bin/clang --print-runtime-dir))/linux
	touch $@

.PHONY: android-x86
android-x86: android-x86.stamp

android.stamp: android-armv7.stamp android-armv8.stamp android-x86.stamp
	touch $@

.PHONY: android
android: android.stamp

.PHONY: android-test
android-test: android
	cd crypto-ffi/bindings && \
	./gradlew android:build -x lint -x lintRelease

#-------------------------------------------------------------------------------
# 8) JVM native builds (Darwin + Linux)
#-------------------------------------------------------------------------------

# darwin build
jvm-darwin.stamp: bindings-kotlin-jvm.stamp
	cd crypto-ffi && \
	$(CARGO) rustc --locked \
	  --target aarch64-apple-darwin \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  --release -- -C strip=symbols
	touch $@

.PHONY: jvm-darwin
jvm-darwin: jvm-darwin.stamp

# linux build
jvm-linux.stamp: bindings-kotlin-jvm.stamp
	cd crypto-ffi && \
	$(CARGO) rustc --locked \
	  --target x86_64-unknown-linux-gnu \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  --release -- -C strip=symbols
	touch $@

.PHONY: jvm-linux
jvm-linux: jvm-linux.stamp

.PHONY: jvm
ifeq ($(UNAME_S),Linux)
jvm: jvm-linux
else ifeq ($(UNAME_S),Darwin)
jvm: jvm-darwin
else
$(error Unsupported host platform for jvm: $(UNAME_S))
endif

.PHONY: jvm-test
jvm-test: jvm
	cd crypto-ffi/bindings && \
	./gradlew jvm:build -x lint -x lintRelease


#-------------------------------------------------------------------------------
# 9) Aggregate targets
#-------------------------------------------------------------------------------

.PHONY: mobile wasm all
mobile: android ios
wasm: bindings-js
all: mobile wasm docs

# ────────────────────────────────────────────────────────────────────────
# TypeScript / JS tasks (from crypto-ffi/bindings/js/package.json)
# ────────────────────────────────────────────────────────────────────────

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
ts-clean:
	@rm -f $(JS_OUT) $(DTS_OUT) \
	&& rm -rf $(GEN_DIR)

ts-fmt.stamp: $(TS_SRCS)
	cd $(JS_DIR) && bun eslint --max-warnings=0 --fix
	touch $@

.PHONY: ts-fmt
ts-fmt: ts-fmt.stamp

$(JS_GEN): wasm-build
$(WASM_GEN): wasm-build

# build corecrypto.js
$(JS_OUT): bun-deps.stamp $(JS_GEN) $(WASM_GEN) $(TS_SRCS) $(PACKAGE_JSON)
	cd $(JS_DIR) && \
	bun build \
	  --target browser \
	  --format esm \
	  --outfile src/corecrypto.js \
	  src/CoreCrypto.ts
	touch $@

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
	touch $@

.PHONY: ts
ts: $(DTS_OUT)

# run WebDriver tests + bun’s built-in tests
.PHONY: ts-test
ts-test: ts
	cd $(JS_DIR) && \
	bun x wdio run wdio.conf.ts --spec test/wdio/*.test.ts && \
	bun test

# run WebDriver benches
.PHONY: ts-bench
ts-bench: ts
	cd $(JS_DIR) && \
	bun x wdio run wdio.conf.ts --spec benches/**/*.bench.ts --log-level warn
