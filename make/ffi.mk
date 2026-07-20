#-------------------------------------------------------------------------------
# Build FFI artifacts
#-------------------------------------------------------------------------------

# Build bindgen binary (independent of rust sources changing)
#
# We need to build this binary if it does not exist, or if the uniffi version
# has changed (see https://github.com/mozilla/uniffi-rs/issues/2622).
GET_UNIFFI_VERSION = perl -ne 'print "$1\n" if /^uniffi\s=\s"([^"]+)"/' Cargo.toml
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

# Build a separate feature-enabled host library for Swift binding generation.
SWIFT_FFI_TARGET_DIR := target/swift-bindgen
SWIFT_FFI_LIBRARY := $(SWIFT_FFI_TARGET_DIR)/$(RELEASE_MODE)/libcore_crypto_ffi.dylib
swift-ffi-library-deps := $(RUST_SOURCES)
$(SWIFT_FFI_LIBRARY): $(swift-ffi-library-deps)
	cargo build $(SWIFT_CARGO_BUILD_ARGS) \
		--target-dir $(SWIFT_FFI_TARGET_DIR) \
		--locked \
		--package core-crypto-ffi \
		--lib

# Make aliases
.PHONY: uniffi-bindgen ffi-library swift-ffi-library
uniffi-bindgen: $(UNIFFI_BINDGEN)  ## Build the uniffi bindgen binary
ffi-library: $(FFI_LIBRARY) ## Build the libcore_crypto_ffi library
swift-ffi-library: $(SWIFT_FFI_LIBRARY) ## Build the feature-enabled host library for Swift bindgen

#-------------------------------------------------------------------------------
# Use stamp files for generators: only re-run when inputs change
#-------------------------------------------------------------------------------

bindings-deps := $(UNIFFI_BINDGEN) $(FFI_LIBRARY)
swift-bindings-deps := $(UNIFFI_BINDGEN) $(SWIFT_FFI_LIBRARY)

# Swift bindings
UNIFFI_SWIFT_OUTPUT := crypto-ffi/bindings/swift/WireCoreCryptoUniffi/WireCoreCryptoUniffi/core_crypto_ffi.swift

ifneq ($(UNAME_S),Darwin)
$(UNIFFI_SWIFT_OUTPUT):
	$(warning Skipping build for "bindings-swift", as swift bindings generation is only supported on \
	          Darwin because OpenSSL can't be cross-compiled on non-Darwin systems; this is "$(UNAME_S)".)
else
$(UNIFFI_SWIFT_OUTPUT): $(swift-bindings-deps)
	mkdir -p crypto-ffi/bindings/swift/WireCoreCryptoUniffi/WireCoreCryptoUniffi
	$(UNIFFI_BINDGEN) generate \
	  --config crypto-ffi/uniffi.toml \
	  --language swift \
	  --out-dir crypto-ffi/bindings/swift/WireCoreCryptoUniffi/WireCoreCryptoUniffi \
	  --library $(SWIFT_FFI_LIBRARY)
endif

.PHONY: bindings-swift swift
bindings-swift-deps := $(swift-bindings-deps)
bindings-swift: $(UNIFFI_SWIFT_OUTPUT) ## Generate Swift bindings

swift: bindings-swift $(STAMPS)/docs-swift

# Kotlin-Android bindings
UNIFFI_ANDROID_OUTPUT := crypto-ffi/bindings/android/src/main/uniffi/com/wire/crypto/core_crypto_ffi.kt

$(UNIFFI_ANDROID_OUTPUT): $(bindings-deps)
	mkdir -p crypto-ffi/bindings/android/src/main/uniffi
	$(UNIFFI_BINDGEN) generate \
	  --config crypto-ffi/uniffi-android.toml \
	  --language kotlin \
	  --no-format \
	  --out-dir crypto-ffi/bindings/android/src/main/uniffi \
	  --library $(FFI_LIBRARY)

.PHONY: bindings-kotlin-android
bindings-kotlin-android-deps := $(bindings-deps)
bindings-kotlin-android: $(UNIFFI_ANDROID_OUTPUT)  ## Generate Kotlin bindings for Android

# Kotlin-JVM bindings
UNIFFI_JVM_OUTPUT := crypto-ffi/bindings/jvm/src/main/uniffi/com/wire/crypto/core_crypto_ffi.kt

$(UNIFFI_JVM_OUTPUT): $(bindings-deps)
	mkdir -p crypto-ffi/bindings/jvm/src/main/uniffi
	$(UNIFFI_BINDGEN) generate \
	  --config crypto-ffi/uniffi.toml \
	  --language kotlin \
	  --no-format \
	  --out-dir crypto-ffi/bindings/jvm/src/main/uniffi \
	  --library $(FFI_LIBRARY)

.PHONY: bindings-kotlin-jvm
bindings-kotlin-jvm-deps := $(bindings-deps)
bindings-kotlin-jvm: $(UNIFFI_JVM_OUTPUT) ## Generate Kotlin bindings for JVM

# Grouped Kotlin bindings
.PHONY: bindings-kotlin
bindings-kotlin: bindings-kotlin-android bindings-kotlin-jvm ## Generate all Kotlin bindings
