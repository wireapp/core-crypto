#-------------------------------------------------------------------------------
# TypeScript / JS tasks
#-------------------------------------------------------------------------------

TS_OUT_DIR := $(JS_DIR)/out
WASM_TARGET_DIR := target/wasm
WASM_BUILD_ENV := CARGO_TARGET_DIR=$(abspath $(WASM_TARGET_DIR))
WASM_TARGET_TRIPLE := wasm32-unknown-unknown
# We are accepting warnings on the generated code when running `cargo check`, this is consistent with the ubrn config.
WASM_BUILD_RUSTFLAGS := --cfg getrandom_backend=\"wasm_js\" -Awarnings
WASM_FFI_LIB := $(WASM_TARGET_DIR)/debug/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
RUST_MODULES_WASM := $(JS_DIR)/rust_modules/wasm
RUST_MODULES_STAMP := $(RUST_MODULES_WASM)/Cargo.toml
RUST_MODULES_CARGO_LOCK := $(RUST_MODULES_WASM)/Cargo.lock
WASM_FILE := $(abspath $(RUST_MODULES_WASM)/target/$(WASM_TARGET_TRIPLE)/$(RELEASE_MODE)/core_crypto_ffi_wasm.wasm)
BROWSER_TS_IMPL := $(BROWSER_GEN_DIR)/core_crypto_ffi.ts
BROWSER_OUT_DIR := $(TS_OUT_DIR)/browser
TS_NATIVE_OUT_DIR := $(TS_OUT_DIR)/native
BROWSER_OUT := $(BROWSER_OUT_DIR)/corecrypto.d.ts $(BROWSER_OUT_DIR)/corecrypto.js
TS_NATIVE_TARGET_DIR := target/napi
TS_NATIVE_BUILD_ENV := CARGO_TARGET_DIR=$(abspath $(TS_NATIVE_TARGET_DIR))
TS_NATIVE_RUNTIME_DIR := $(JS_DIR)/node_modules/uniffi-bindgen-react-native/runtimes/napi
TS_NATIVE_DARWIN_TARGET ?= aarch64-apple-darwin
TS_NATIVE_DARWIN_RUNTIME_NODE ?= uniffi-runtime-napi.darwin-arm64.node
TS_NATIVE_LINUX_TARGET ?= x86_64-unknown-linux-gnu
TS_NATIVE_LINUX_RUNTIME_NODE ?= uniffi-runtime-napi.linux-x64-gnu.node
ifeq ($(UNAME_S),Linux)
TS_NATIVE_TARGET_TRIPLE ?= $(TS_NATIVE_LINUX_TARGET)
TS_NATIVE_RUNTIME_NODE ?= $(TS_NATIVE_LINUX_RUNTIME_NODE)
else ifeq ($(UNAME_S),Darwin)
TS_NATIVE_TARGET_TRIPLE ?= $(TS_NATIVE_DARWIN_TARGET)
TS_NATIVE_RUNTIME_NODE ?= $(TS_NATIVE_DARWIN_RUNTIME_NODE)
else
$(error Unsupported host platform for ts-native: $(UNAME_S))
endif
TS_NATIVE_FFI_LIB := $(abspath $(TS_NATIVE_TARGET_DIR))/$(TS_NATIVE_TARGET_TRIPLE)/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
TS_NATIVE_OUT := \
	$(TS_NATIVE_GEN_DIR)/core_crypto_ffi.ts \
	$(TS_NATIVE_GEN_DIR)/core_crypto_ffi-ffi.ts \
	$(TS_NATIVE_OUT_DIR)/corecrypto.d.ts \
	$(TS_NATIVE_OUT_DIR)/corecrypto.js \
	$(TS_NATIVE_OUT_DIR)/$(TS_NATIVE_RUNTIME_NODE) \
	$(TS_NATIVE_OUT_DIR)/libcore_crypto_ffi.$(LIBRARY_EXTENSION)

TS_OUT := $(BROWSER_OUT) $(TS_NATIVE_OUT)

# In release mode, fail if the lockfile does not match
BUN_FROZEN_LOCKFILE := $(if $(RELEASE),--frozen-lockfile)

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
bun-deps: $(BUN_LOCK) $(NODE_MODULES) ## Install JS dependencies using bun

# always remove old outputs
.PHONY: ts-clean
ts-clean: ## Cleanup old TypeScript build outputs
	@rm -rf $(TS_OUT_DIR) \
	&& rm -rf $(BROWSER_GEN_DIR) \
	&& rm -rf $(TS_NATIVE_GEN_DIR) \
	&& rm -rf $(WASM_TARGET_DIR) \
	&& rm -rf $(JS_DIR)/rust_modules

ubrn-deps := $(RUST_SOURCES)
$(WASM_FFI_LIB) $(BROWSER_TS_IMPL) $(RUST_MODULES_STAMP) &: $(ubrn-deps)
	cd $(JS_DIR) && $(WASM_BUILD_ENV) bun ubrn build web --no-wasm-pack
	touch $(RUST_MODULES_STAMP)

$(RUST_MODULES_CARGO_LOCK): Cargo.lock $(RUST_MODULES_STAMP)
	cp Cargo.lock $(RUST_MODULES_CARGO_LOCK)

$(WASM_FILE): $(RUST_MODULES_CARGO_LOCK) $(RUST_MODULES_STAMP)
	cd $(RUST_MODULES_WASM) && \
	RUSTFLAGS="$(WASM_BUILD_RUSTFLAGS)" cargo build --target $(WASM_TARGET_TRIPLE) $(CARGO_BUILD_ARGS)

WASM_GEN := \
	$(BROWSER_GEN_DIR)/wasm-bindgen/index_bg.wasm \
	$(BROWSER_GEN_DIR)/wasm-bindgen/index_bg.wasm.d.ts \
	$(BROWSER_GEN_DIR)/wasm-bindgen/index.d.ts \
	$(BROWSER_GEN_DIR)/wasm-bindgen/index.js

# All our actual dependencies for this step are generated, so we fake it by listing the ancestor dependencies
wasm-build-deps := $(ubrn-deps) Cargo.lock
# index.web.ts is generated but unused so we remove it
# Build the temporary host library in a dedicated target dir so we do not mix
# the shared target outputs used by ios/jvm builds.
$(WASM_GEN) &: $(wasm-build-deps)
# Depend on source files, not $(WASM_FILE) directly. The CI artifact system restores
# $(WASM_GEN) outputs on macOS runners where clang cannot build wasm32-unknown-unknown.
# Source-file deps let Make treat those restored files as up-to-date without needing
# $(WASM_FILE) to exist; a direct prerequisite would force a rebuild attempt that fails.
	$(MAKE) $(WASM_FILE)
	cd $(JS_DIR) && \
	wasm-bindgen --target web \
	  --omit-default-module-path \
	  --out-name index \
	  --out-dir packages/browser/src/autogenerated/wasm-bindgen \
	  $(WASM_FILE) && \
	rm src/index.web.ts
.PHONY: wasm-build
wasm-build: $(WASM_GEN)

# generate TypeScript defs only when corecrypto.js changed
ts-browser-deps := $(TS_BROWSER_SRCS) $(WASM_GEN) $(BUN_LOCK) $(NODE_MODULES) $(PACKAGE_JSON) $(BUNFIG)
$(BROWSER_OUT) &: $(ts-browser-deps)
	cd $(JS_DIR) && \
	bun build packages/browser/src/CoreCrypto.ts \
	  --conditions=cc-browser \
	  --target browser \
	  --format esm \
	  --outdir out/browser \
	  --entry-naming "corecrypto.[ext]" && \
	mkdir -p out/browser/autogenerated/ && \
	mkdir -p out/browser/autogenerated/wasm-bindgen && \
	cp packages/browser/src/autogenerated/wasm-bindgen/index_bg.wasm out/browser/autogenerated/wasm-bindgen/ && \
	cp packages/browser/src/autogenerated/wasm-bindgen/index_bg.wasm.d.ts out/browser/autogenerated/wasm-bindgen/ && \
	bun x dts-bundle-generator \
	  --project packages/browser/tsconfig.json \
	  -o out/browser/corecrypto.d.ts \
	  --no-check \
	  --export-referenced-types false \
	  packages/browser/src/CoreCrypto.ts
	@touch $@

.PHONY: ts-browser
ts-browser: $(BROWSER_OUT) ## Build the TypeScript wrapper for the browser

ts-native-deps := $(TS_NATIVE_SRCS) $(RUST_SOURCES) $(BUN_LOCK) $(NODE_MODULES) $(PACKAGE_JSON) $(BUNFIG)
$(TS_NATIVE_OUT) &: $(ts-native-deps)
	cd $(JS_DIR) && \
	rm -rf out/native && \
	rm -rf packages/native/src/autogenerated && \
	mkdir -p out/native/autogenerated && \
	mkdir -p packages/native/src/autogenerated && \
	$(TS_NATIVE_BUILD_ENV) cargo build $(CARGO_BUILD_ARGS) \
		--locked \
		--package core-crypto-ffi \
		--lib \
		--features napi \
		--target $(TS_NATIVE_TARGET_TRIPLE) && \
	cd $(CURDIR) && \
	$(TS_NATIVE_BUILD_ENV) RUSTFLAGS="$(RUSTFLAGS) -Awarnings" $(abspath $(JS_DIR)/node_modules/.bin/ubrn) generate napi bindings \
		--library \
		--ts-dir $(abspath $(TS_NATIVE_GEN_DIR)) \
		$(TS_NATIVE_FFI_LIB) && \
	perl -0pi -e 's#import \\{ createRequire \\} from "node:module";\\n\\nconst require = createRequire\\(import\\.meta\\.url\\);\\nconst lib = require\\("uniffi-bindgen-react-native/runtimes/napi/lib\\.js"\\);#import lib from "../runtime/uniffiRuntime";#' $(abspath $(TS_NATIVE_GEN_DIR))/core_crypto_ffi-ffi.ts && \
	cd $(abspath $(JS_DIR)) && \
	bun build packages/native/src/CoreCrypto.ts \
	  --conditions=cc-native \
	  --target node \
	  --format esm \
	  --outdir out/native \
	  --entry-naming "corecrypto.[ext]" && \
	cp $(abspath $(TS_NATIVE_RUNTIME_DIR))/$(TS_NATIVE_RUNTIME_NODE) out/native/$(TS_NATIVE_RUNTIME_NODE) && \
	cp $(TS_NATIVE_FFI_LIB) out/native/libcore_crypto_ffi.$(LIBRARY_EXTENSION) && \
	bun x dts-bundle-generator \
	  --project packages/native/tsconfig.json \
	  -o out/native/corecrypto.d.ts \
	  --no-check \
	  --export-referenced-types false \
	  packages/native/src/CoreCrypto.ts

ts-native-darwin-deps := $(ts-native-deps)
.PHONY: ts-native-darwin
ts-native-darwin: ## Build the native TypeScript wrapper for aarch64-apple-darwin
	$(MAKE) TS_NATIVE_TARGET_TRIPLE=$(TS_NATIVE_DARWIN_TARGET) TS_NATIVE_RUNTIME_NODE=$(TS_NATIVE_DARWIN_RUNTIME_NODE) ts-native

ts-native-linux-deps := $(ts-native-deps)
.PHONY: ts-native-linux
ts-native-linux: ## Build the native TypeScript wrapper for x86_64-unknown-linux-gnu
	$(MAKE) TS_NATIVE_TARGET_TRIPLE=$(TS_NATIVE_LINUX_TARGET) TS_NATIVE_RUNTIME_NODE=$(TS_NATIVE_LINUX_RUNTIME_NODE) ts-native

.PHONY: ts-native
ts-native: $(TS_NATIVE_OUT) ## Build the native TypeScript wrapper (automatically select the target based on the host machine)

ts-browser-test-deps := $(BROWSER_OUT) $(TS_BROWSER_TEST_FILES)

# run browser-oriented TypeScript tests (WebDriver + Bun wasm)
$(STAMPS)/ts-browser-test: $(ts-browser-test-deps)
	@set -euo pipefail; \
	cd $(JS_DIR) && \
	if [ -n "$(TEST)" ]; then \
		bun x wdio run ./packages/browser/test/wdio.test.conf.ts --mochaOpts.grep "$(TEST)"; \
	else \
		bun x wdio run ./packages/browser/test/wdio.test.conf.ts; \
	fi
	$(TOUCH_STAMP)

ts-native-test-deps := $(TS_NATIVE_OUT) $(TS_NATIVE_TEST_FILES)

# run native TypeScript tests (Bun napi)
$(STAMPS)/ts-native-test: $(ts-native-test-deps)
	@set -euo pipefail; \
	cd $(JS_DIR) && \
	if [ -n "$(TEST)" ]; then \
		bun --conditions=cc-native test --filter "$(TEST)" ./packages/native/test; \
	else \
		bun --conditions=cc-native test ./packages/native/test; \
	fi
	$(TOUCH_STAMP)

$(STAMPS)/ts-test:
	@$(MAKE) LAZY_MAKE= ts-browser-test TEST="$(TEST)"
	@$(MAKE) LAZY_MAKE= ts-native-test TEST="$(TEST)"
	$(TOUCH_STAMP)

# run WebDriver benches
.PHONY: ts-browser-bench
ts-browser-bench: $(BROWSER_OUT) ## Run TypeScript wrapper benches in Chrome via wdio
	@set -euo pipefail; \
	cd $(JS_DIR) && \
	if [ -n "$(BENCH)" ]; then \
		bun x wdio run ./packages/browser/benches/wdio.bench.conf.ts --mochaOpts.grep "$(BENCH)"; \
	else \
		bun x wdio run ./packages/browser/benches/wdio.bench.conf.ts --log-level warn; \
	fi

.PHONY: ts-native-bench
ts-native-bench: $(TS_NATIVE_OUT)
	@set -euo pipefail; \
	cd $(JS_DIR) && \
	bench_files="./packages/native/benches/*.bench.ts"; \
	if [ -n "$(BENCH)" ]; then \
		bench_files="./packages/native/benches/*$(BENCH)*.bench.ts"; \
	fi; \
	for f in $$bench_files; do \
		bun --conditions=cc-native run "$$f"; \
	done

.PHONY: ts-package
ts-package: $(TS_OUT)  ## Package the ready-to-release tarball
	@cd $(JS_DIR) && \
	bun pm pack --quiet
