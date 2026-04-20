#-------------------------------------------------------------------------------
# JVM native builds (Darwin + Linux)
#-------------------------------------------------------------------------------

# darwin build
JVM_DARWIN_LIB := target/aarch64-apple-darwin/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
jvm-darwin-deps := $(RUST_SOURCES)
$(JVM_DARWIN_LIB): $(jvm-darwin-deps)
	cargo rustc --locked \
	  --target aarch64-apple-darwin \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)
.PHONY: jvm-darwin
jvm-darwin: $(JVM_DARWIN_LIB) ## Build core-crypto-ffi for JVM on aarch64-apple-darwin

# linux build
JVM_LINUX_LIB := target/x86_64-unknown-linux-gnu/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
jvm-linux-deps := $(RUST_SOURCES)
$(JVM_LINUX_LIB): $(jvm-linux-deps)
	cargo rustc --locked \
	  --target x86_64-unknown-linux-gnu \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)

.PHONY: jvm-linux
jvm-linux: $(JVM_LINUX_LIB) ## Build core-crypto-ffi for JVM on x86_64-unknown-linux-gnu

.PHONY: jvm
ifeq ($(UNAME_S),Linux)
JVM_LIB := $(JVM_LINUX_LIB)
jvm-deps := $(jvm-linux-deps)
jvm: jvm-linux ## Build core-crypto-ffi for JVM (automatically select the target based on the host machine)
else ifeq ($(UNAME_S),Darwin)
JVM_LIB := $(JVM_DARWIN_LIB)
jvm-deps := $(jvm-darwin-deps)
jvm: jvm-darwin
else
$(error Unsupported host platform for jvm: $(UNAME_S))
endif

jvm-test-deps := $(JVM_LIB) $(UNIFFI_JVM_OUTPUT) $(KT_FILES)

$(STAMPS)/jvm-test: $(jvm-test-deps)
	cd crypto-ffi/bindings && \
	./gradlew jvm:test --rerun
	$(TOUCH_STAMP)

.PHONY: jvm-bench
	@set -euo pipefail; \
	cd crypto-ffi/bindings && \
	if [ -n "$(BENCH)" ]; then \
		./gradlew :jvm:jmh -PjmhIncludes=$(BENCH); \
	else \
		./gradlew :jvm:jmh; \
	fi

#-------------------------------------------------------------------------------
# KMP (Kotlin Multiplatform) builds
#-------------------------------------------------------------------------------

kmp-jvm-test-deps := $(FFI_LIBRARY) $(JVM_LIB) $(KT_FILES)

$(STAMPS)/kmp-jvm-test: $(kmp-jvm-test-deps)
	cd crypto-ffi/bindings && \
	./gradlew core-crypto-kmp:jvmTest --rerun
	$(TOUCH_STAMP)
