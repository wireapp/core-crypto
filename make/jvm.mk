#-------------------------------------------------------------------------------
# JVM native builds (Darwin + Linux)
#-------------------------------------------------------------------------------

# darwin build
JVM_DARWIN_LIB := target/aarch64-apple-darwin/$(RELEASE_MODE)/libcore_crypto_ffi.dylib
jvm-darwin-deps := $(RUST_SOURCES)
$(JVM_DARWIN_LIB): $(jvm-darwin-deps)
	cargo rustc --locked \
	  --target aarch64-apple-darwin \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)
.PHONY: jvm-darwin
jvm-darwin: $(JVM_DARWIN_LIB) ## Build core-crypto-ffi for JVM on aarch64-apple-darwin

# linux x86_64 build
JVM_LINUX_X86_64_TARGET := x86_64-unknown-linux-gnu
JVM_LINUX_X86_64_LIB := target/$(JVM_LINUX_X86_64_TARGET)/$(RELEASE_MODE)/libcore_crypto_ffi.so
jvm-linux-x86-64-deps := $(RUST_SOURCES)
$(JVM_LINUX_X86_64_LIB): $(jvm-linux-x86-64-deps)
	cargo rustc --locked \
	  --target $(JVM_LINUX_X86_64_TARGET) \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)

.PHONY: jvm-linux-x86-64
jvm-linux-x86-64: $(JVM_LINUX_X86_64_LIB) ## Build core-crypto-ffi for JVM on x86_64-unknown-linux-gnu

# linux aarch64 build
JVM_LINUX_AARCH64_TARGET := aarch64-unknown-linux-gnu
JVM_LINUX_AARCH64_LIB := target/$(JVM_LINUX_AARCH64_TARGET)/$(RELEASE_MODE)/libcore_crypto_ffi.so
jvm-linux-aarch64-deps := $(RUST_SOURCES)
$(JVM_LINUX_AARCH64_LIB): $(jvm-linux-aarch64-deps)
	cargo rustc --locked \
	  --target $(JVM_LINUX_AARCH64_TARGET) \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)

.PHONY: jvm-linux-aarch64
jvm-linux-aarch64: $(JVM_LINUX_AARCH64_LIB) ## Build core-crypto-ffi for JVM on aarch64-unknown-linux-gnu

.PHONY: jvm-linux
ifeq ($(UNAME_M),x86_64)
JVM_LINUX_LIB := $(JVM_LINUX_X86_64_LIB)
jvm-linux-deps := $(jvm-linux-x86-64-deps)
jvm-linux: jvm-linux-x86-64 ## Build core-crypto-ffi for JVM on Linux (automatically select the target based on the host architecture)
else ifneq ($(filter $(UNAME_M),aarch64 arm64),)
JVM_LINUX_LIB := $(JVM_LINUX_AARCH64_LIB)
jvm-linux-deps := $(jvm-linux-aarch64-deps)
jvm-linux: jvm-linux-aarch64
else
$(error Unsupported Linux architecture for jvm: $(UNAME_M))
endif

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
jvm-bench: $(jvm-test-deps) $(KT_BENCHMARKS) ## Run the JVM benchmarks
	@set -euo pipefail; \
	cd crypto-ffi/bindings && \
	GRADLE_ARGS=""; \
	if [ -n "$(BENCH)" ]; then \
		GRADLE_ARGS="$$GRADLE_ARGS -PjmhIncludes=$(BENCH)"; \
	fi; \
	if [ -n "$(BENCHMARK_MESSAGE_COUNTS)" ]; then \
		GRADLE_ARGS="$$GRADLE_ARGS -PjmhBenchmarkMessageCounts=$(BENCHMARK_MESSAGE_COUNTS)"; \
	fi; \
	if [ -n "$(BENCHMARK_MESSAGE_SIZES)" ]; then \
		GRADLE_ARGS="$$GRADLE_ARGS -PjmhBenchmarkMessageSizes=$(BENCHMARK_MESSAGE_SIZES)"; \
	fi; \
	if [ -n "$(BENCHMARK_USER_COUNTS)" ]; then \
		GRADLE_ARGS="$$GRADLE_ARGS -PjmhBenchmarkUserCounts=$(BENCHMARK_USER_COUNTS)"; \
	fi; \
	if [ -n "$(BENCHMARK_CIPHER_SUITES)" ]; then \
		GRADLE_ARGS="$$GRADLE_ARGS -PjmhBenchmarkCipherSuites=$(BENCHMARK_CIPHER_SUITES)"; \
	fi; \
	if [ -n "$(PROFILE)" ]; then \
		GRADLE_ARGS="$$GRADLE_ARGS -Pprofile"; \
	fi; \
	./gradlew :jvm:jmh $$GRADLE_ARGS

#-------------------------------------------------------------------------------
# KMP (Kotlin Multiplatform) builds
#-------------------------------------------------------------------------------

kmp-jvm-test-deps := $(FFI_LIBRARY) $(JVM_LIB) $(KT_FILES)

$(STAMPS)/kmp-jvm-test: $(kmp-jvm-test-deps)
	cd crypto-ffi/bindings && \
	./gradlew core-crypto-kmp:jvmTest --rerun
	$(TOUCH_STAMP)
