#-------------------------------------------------------------------------------
# Formatting and linting
#-------------------------------------------------------------------------------

# Rust

$(STAMPS)/rust-fmt: $(RUST_SOURCES)
	cargo +nightly fmt --all
	$(TOUCH_STAMP)

.PHONY: rust-fmt
rust-fmt: $(STAMPS)/rust-fmt ## Format Rust files via cargo fmt

$(STAMPS)/rust-check: $(RUST_SOURCES)
	cargo +nightly fmt --all -- --check && \
	cargo check --locked --all-targets && \
	cargo check --locked --target wasm32-unknown-unknown && \
    cargo clippy --locked --all-targets && \
    cargo clippy --locked --target wasm32-unknown-unknown
	$(TOUCH_STAMP)

.PHONY: rust-check
rust-check: $(STAMPS)/rust-check ## Lint Rust files via cargo clippy and cargo check

# Swift

$(STAMPS)/swift-fmt: $(SWIFT_FILES)
	swift format -r -i $(SWIFT_INTEROP) $(SWIFT_TESTS) $(SWIFT_WRAPPER)
	$(TOUCH_STAMP)

.PHONY: swift-fmt
swift-fmt: $(STAMPS)/swift-fmt ## Format Swift files via swift-format

$(STAMPS)/swift-check: $(SWIFT_FILES)
	swift format lint -r -s $(SWIFT_INTEROP) $(SWIFT_TESTS) $(SWIFT_WRAPPER) && \
	swiftlint --strict  $(SWIFT_INTEROP) $(SWIFT_TESTS) $(SWIFT_WRAPPER)
	$(TOUCH_STAMP)

.PHONY: swift-check
swift-check: $(STAMPS)/swift-check ## Lint Swift files via swift-format and swift-lint

# Kotlin

$(STAMPS)/kotlin-fmt: $(KT_FILES) $(KT_GRADLE_FILES)
	ktlint --format $(KT_FILES) $(KT_GRADLE_FILES)
	$(TOUCH_STAMP)

.PHONY: kotlin-fmt
kotlin-fmt: $(STAMPS)/kotlin-fmt ## Format Kotlin files via ktlint

$(STAMPS)/kotlin-check: $(KT_FILES) $(KT_GRADLE_FILES)
	ktlint $(KT_FILES) $(KT_GRADLE_FILES)
	$(TOUCH_STAMP)

.PHONY: kotlin-check
kotlin-check: $(STAMPS)/kotlin-check ## Lint Kotlin files via ktlint

# TypeScript

$(STAMPS)/ts-fmt: $(TS_SRCS) $(TS_TEST_FILES) $(TS_BENCH_FILES)
	cd $(JS_DIR) && bun eslint --max-warnings=0 --fix
	$(TOUCH_STAMP)

.PHONY: ts-fmt
ts-fmt: $(STAMPS)/ts-fmt ## Format TypeScript files via eslint

$(STAMPS)/ts-check: $(TS_SRCS) $(TS_TEST_FILES) $(TS_BENCH_FILES) $(BROWSER_OUT) $(TS_NATIVE_OUT)
	cd $(JS_DIR) && bun eslint --max-warnings=0 && \
	bun x tsc --noEmit --project ./packages/browser/tsconfig.json && \
	bun x tsc --noEmit --project ./packages/native/tsconfig.json
	$(TOUCH_STAMP)

.PHONY: ts-check
ts-check: $(STAMPS)/ts-check ## Lint TypeScript files via eslint and tsc

.PHONY: fmt
fmt: rust-fmt swift-fmt kotlin-fmt ts-fmt ## Format all files

.PHONY: check
check: rust-check swift-check kotlin-check ts-check ## Run all linters
