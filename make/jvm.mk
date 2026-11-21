#-------------------------------------------------------------------------------
# JVM native builds (Darwin, Linux and Windows)
#-------------------------------------------------------------------------------

# darwin build
JVM_DARWIN_LIB := target/aarch64-apple-darwin/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
jvm-darwin-deps := $(RUST_SOURCES)
$(JVM_DARWIN_LIB): $(jvm-darwin-deps)
	cargo rustc --locked \
	  --target aarch64-apple-darwin \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(DARWIN_CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)
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
	  $(NATIVE_CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)

.PHONY: jvm-linux
jvm-linux: $(JVM_LINUX_LIB) ## Build core-crypto-ffi for JVM on x86_64-unknown-linux-gnu

# windows build
#
# Windows libraries have no `lib` prefix. Only the dynamic library is built: the static library
# is for Kotlin/Native consumers, and there's no Windows Kotlin/Native target.
JVM_WINDOWS_LIB := target/x86_64-pc-windows-msvc/$(RELEASE_MODE)/core_crypto_ffi.dll
jvm-windows-deps := $(RUST_SOURCES)
#
# Without NASM on the `PATH`, the vendored OpenSSL quietly builds without its assembly routines,
# losing AES-NI and the constant-time implementations. Require it.
#
# The vendored OpenSSL builds with nmake, which reads `MAKEFLAGS` too and rejects GNU make's
# (e.g. ` -- RELEASE=1`), so clear them. nmake also takes `MAKE` from the environment, where CI
# sets it, and would run GNU make on its own makefiles, so remove that.
#
# Link the C runtime statically, so the library loads on machines without the Visual C++
# Redistributable. It goes in `RUSTFLAGS` so that the C dependencies build against it too.
$(JVM_WINDOWS_LIB): $(jvm-windows-deps)
	env -u MAKE MAKEFLAGS= MFLAGS= OPENSSL_RUST_USE_NASM=1 \
	RUSTFLAGS="$${RUSTFLAGS:-} -C target-feature=+crt-static" \
	cargo rustc --locked \
	  --target x86_64-pc-windows-msvc \
	  --package core-crypto-ffi \
	  --crate-type=cdylib \
	  $(NATIVE_CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)

.PHONY: jvm-windows
jvm-windows: $(JVM_WINDOWS_LIB) ## Build core-crypto-ffi for JVM on x86_64-pc-windows-msvc

.PHONY: jvm
ifeq ($(UNAME_S),Linux)
JVM_LIB := $(JVM_LINUX_LIB)
jvm: jvm-linux ## Build core-crypto-ffi for JVM (automatically select the target based on the host machine)
else ifeq ($(UNAME_S),Darwin)
JVM_LIB := $(JVM_DARWIN_LIB)
jvm: jvm-darwin
else ifeq ($(UNAME_S),Windows)
JVM_LIB := $(JVM_WINDOWS_LIB)
jvm: jvm-windows
else
$(error Unsupported host platform for jvm: $(UNAME_S))
endif

jvm-test-deps := $(JVM_LIB) $(UNIFFI_JVM_OUTPUT) $(KT_FILES) $(KT_BUILD_FILES)

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

kmp-jvm-test-deps := $(FFI_LIBRARY) $(JVM_LIB) $(KT_FILES) $(KT_BUILD_FILES)

$(STAMPS)/kmp-jvm-test: $(kmp-jvm-test-deps)
	cd crypto-ffi/bindings && \
	./gradlew core-crypto-kmp:jvmTest --rerun
	$(TOUCH_STAMP)
