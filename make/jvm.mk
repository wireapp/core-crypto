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
	  $(DARWIN_CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)
.PHONY: jvm-darwin
jvm-darwin: $(JVM_DARWIN_LIB) ## Build core-crypto-ffi for JVM on aarch64-apple-darwin

# linux builds
#
# The Linux libraries link against the glibc they are built with. In CI, or with
# JVM_LINUX_MANYLINUX=1 on a Linux host with Docker, cargo runs in a manylinux_2_28 container
# (scripts/in-manylinux.sh), so that the libraries need glibc 2.28 at most. The container build has
# its own target directory, because objects from host builds link against the host's glibc. The
# libraries are then copied to where a host build puts them, checked and loaded.
JVM_LINUX_MANYLINUX ?= $(if $(filter 1 true yes,$(CI)),1,)
jvm-linux-manylinux := $(filter 1 true yes,$(JVM_LINUX_MANYLINUX))
JVM_MANYLINUX_TARGET_DIR := target/manylinux_2_28

# $(call jvm-linux-cargo,<arch>): cargo on the host, or in the container for <arch>
jvm-linux-cargo = $(if $(jvm-linux-manylinux),scripts/in-manylinux.sh $(1) env CARGO_TARGET_DIR=$(JVM_MANYLINUX_TARGET_DIR)) cargo

# $(call jvm-linux-finish,<arch>,<triple>,<library>): after a container build, copy the libraries into
# place, then check in the container that the shared library needs glibc 2.28 at most and loads. If
# not, both libraries are removed.
jvm-linux-finish = $(if $(jvm-linux-manylinux),\
	mkdir -p $(dir $(3)) && \
	cp $(addprefix $(JVM_MANYLINUX_TARGET_DIR)/$(2)/$(RELEASE_MODE)/libcore_crypto_ffi.,$(LIBRARY_EXTENSION) a) $(dir $(3)) && \
	scripts/in-manylinux.sh $(1) scripts/check-linux-library.sh $(3) 2.28 || \
	{ rm -f $(3) $(patsubst %.$(LIBRARY_EXTENSION),%.a,$(3)); exit 1; })

JVM_LINUX_LIB := target/x86_64-unknown-linux-gnu/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
jvm-linux-deps := $(RUST_SOURCES) make/jvm.mk scripts/in-manylinux.sh scripts/check-linux-library.sh
$(JVM_LINUX_LIB): $(jvm-linux-deps)
	$(call jvm-linux-cargo,x86_64) rustc --locked \
	  --target x86_64-unknown-linux-gnu \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(NATIVE_CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)
	$(call jvm-linux-finish,x86_64,x86_64-unknown-linux-gnu,$@)

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
