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

# Kotlin docs
KOTLIN_SOURCES := $(shell find crypto-ffi/bindings/shared/src/commonMain/kotlin \
	                           -type f -name '*.kt' 2>/dev/null | LC_ALL=C sort)
docs-kotlin-deps := $(JVM_LIB) $(jvm-deps) $(KOTLIN_SOURCES)
$(STAMPS)/docs-kotlin: $(docs-kotlin-deps)
	cd crypto-ffi/bindings && ./gradlew jvm:dokkaGeneratePublicationHtml
	mkdir -p target/kotlin/doc
	cp -R crypto-ffi/bindings/jvm/build/dokka/html target/kotlin/doc
	$(TOUCH_STAMP)

.PHONY: docs-kotlin
docs-kotlin: $(STAMPS)/docs-kotlin ## Generate Kotlin docs

# TypeScript docs via Typedoc
$(STAMPS)/docs-ts: $(BROWSER_OUT) $(TS_NATIVE_OUT)
	cd crypto-ffi/bindings/js && \
	bun typedoc \
	  --basePath ./ \
	  --displayBasePath ./src \
	  --entryPoints src/browser/CoreCrypto.ts \
	  --entryPoints src/native/CoreCrypto.ts \
	  --tsconfig tsconfig.json \
	  --out ../../../target/typescript/doc \
	  --readme none \
	  --treatWarningsAsErrors \
	  --plugin ./typedoc-ignore-warnings.cjs
	$(TOUCH_STAMP)

.PHONY: docs-ts
docs-ts: $(STAMPS)/docs-ts ## Generate TypeScript docs for the browser

# Swift docs via Jazzy (macOS only)
docs-swift-deps := $(IOS_DEVICE) $(IOS_SIMULATOR_ARM) $(UNIFFI_SWIFT_OUTPUT)
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

$(STAMPS)/cc-book-browser-attachments: $(STAMPS)/docs-ts
	mkdir -p cc-book/modules/browser/attachments
	cp -r target/typescript/doc cc-book/modules/browser/attachments/
	$(TOUCH_STAMP)

$(STAMPS)/cc-book-jvm-attachments: $(STAMPS)/docs-kotlin
	mkdir -p cc-book/modules/jvm/attachments
	cp -r target/kotlin/doc cc-book/modules/jvm/attachments/
	$(TOUCH_STAMP)

# Build the CC book using Antora
.PHONY: cc-book
cc-book: $(STAMPS)/cc-book-browser-attachments $(STAMPS)/cc-book-jvm-attachments
	cd cc-book && \
	bunx antora antora-playbook.yml
