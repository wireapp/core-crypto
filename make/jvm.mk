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
	  $(DARWIN_CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS) $(NATIVE_STATIC_LIBS_FLAGS)
.PHONY: jvm-darwin
jvm-darwin: $(JVM_DARWIN_LIB) ## Build core-crypto-ffi for JVM on aarch64-apple-darwin

# darwin x86_64 build, only shipped in the KMP package
JVM_DARWIN_X86_LIB := target/x86_64-apple-darwin/$(RELEASE_MODE)/libcore_crypto_ffi.dylib
jvm-darwin-x86-deps := $(RUST_SOURCES)
$(JVM_DARWIN_X86_LIB): $(jvm-darwin-x86-deps)
	cargo rustc --locked \
	  --target x86_64-apple-darwin \
	  --package core-crypto-ffi \
	  --crate-type=cdylib \
	  $(DARWIN_CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)
.PHONY: jvm-darwin-x86
jvm-darwin-x86: $(JVM_DARWIN_X86_LIB) ## Build core-crypto-ffi for JVM on x86_64-apple-darwin (macOS only)

# linux build
JVM_LINUX_LIB := target/x86_64-unknown-linux-gnu/$(RELEASE_MODE)/libcore_crypto_ffi.so
jvm-linux-deps := $(RUST_SOURCES)
$(JVM_LINUX_LIB): $(jvm-linux-deps)
	cargo rustc --locked \
	  --target x86_64-unknown-linux-gnu \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(NATIVE_CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)

.PHONY: jvm-linux
jvm-linux: $(JVM_LINUX_LIB) ## Build core-crypto-ffi for JVM on x86_64-unknown-linux-gnu

# linux aarch64 build, only shipped in the KMP package
JVM_LINUX_ARM_LIB := target/aarch64-unknown-linux-gnu/$(RELEASE_MODE)/libcore_crypto_ffi.so
jvm-linux-arm-deps := $(RUST_SOURCES)
$(JVM_LINUX_ARM_LIB): $(jvm-linux-arm-deps)
	cargo rustc --locked \
	  --target aarch64-unknown-linux-gnu \
	  --package core-crypto-ffi \
	  --crate-type=cdylib \
	  $(NATIVE_CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)
.PHONY: jvm-linux-arm
jvm-linux-arm: $(JVM_LINUX_ARM_LIB) ## Build core-crypto-ffi for JVM on aarch64-unknown-linux-gnu (aarch64 Linux only)

# windows build, only shipped in the KMP package. Cross-compiled with mingw-w64.
JVM_WINDOWS_LIB := target/x86_64-pc-windows-gnu/$(RELEASE_MODE)/core_crypto_ffi.dll
jvm-windows-deps := $(RUST_SOURCES)
$(JVM_WINDOWS_LIB): $(jvm-windows-deps)
	cargo rustc --locked \
	  --target x86_64-pc-windows-gnu \
	  --package core-crypto-ffi \
	  --crate-type=cdylib \
	  $(NATIVE_CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)
.PHONY: jvm-windows
jvm-windows: $(JVM_WINDOWS_LIB) ## Build core-crypto-ffi for JVM on x86_64-pc-windows-gnu (needs mingw-w64)

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

# OxiKT packages the libraries make builds in `target`. Debug builds need the host's JVM and
# Android libraries, release builds every JVM and Android library. On macOS, both also need the
# Apple static libraries; elsewhere Kotlin/Native skips the Apple targets.
KMP_GRADLE_ARGS := $(if $(RELEASE),-PreleaseBuild=true) -PprebuiltLibraries=$(abspath target)

# The static library and its linker options, built with the given dynamic library. If they're
# missing, for example after OxiKT's own cargo build, the crate is cleaned and built again, since
# rustc only writes them when it compiles it.
kmp-apple-files = $(basename $(1)).a $(dir $(1))core_crypto_ffi.native-static-libs
kmp-clean-args = --target $(word 2,$(subst /, ,$(1))) --profile $(if $(filter release,$(word 3,$(subst /, ,$(1)))),release,dev)
KMP_APPLE_LIBS := $(IOS_DEVICE) $(IOS_SIMULATOR_ARM) $(JVM_DARWIN_LIB)
$(foreach lib,$(KMP_APPLE_LIBS),$(eval $(call kmp-apple-files,$(lib)): $(lib) ; \
	@test -f $$@ || { cargo clean -p core-crypto-ffi $(call kmp-clean-args,$(lib)) && $$(MAKE) $$< && test -f $$@; }))

# The simulator library is always a release build, but debug builds look for it under `debug`.
KMP_SIMULATOR_FILES := $(subst /release/,/$(RELEASE_MODE)/,$(call kmp-apple-files,$(IOS_SIMULATOR_ARM)))
ifneq ($(RELEASE_MODE),release)
target/aarch64-apple-ios-sim/$(RELEASE_MODE)/%: target/aarch64-apple-ios-sim/release/%
	mkdir -p $(@D) && ln -f $< $@
endif

KMP_RELEASE_LIBS := $(JVM_DARWIN_LIB) $(JVM_DARWIN_X86_LIB) $(JVM_LINUX_LIB) $(JVM_LINUX_ARM_LIB) $(JVM_WINDOWS_LIB) \
	$(ANDROID_ARMv7) $(ANDROID_ARMv8) $(ANDROID_X86)
KMP_LIBS := $(if $(RELEASE),$(KMP_RELEASE_LIBS),$(JVM_LIB) $(ANDROID_TEST_LIB)) \
	$(if $(filter Darwin,$(UNAME_S)),$(foreach lib,$(IOS_DEVICE) $(JVM_DARWIN_LIB),$(call kmp-apple-files,$(lib))) \
	$(KMP_SIMULATOR_FILES))

# What the package publishes. Not `assemble`, which also compiles the native tests, and those use
# JVM-only APIs.
KMP_ARTIFACT_TASKS := allMetadataJar jvmJar bundleAndroidMainAar iosArm64MainKlibrary \
	iosSimulatorArm64MainKlibrary macosArm64MainKlibrary

.PHONY: kmp
kmp-deps := $(RUST_SOURCES) $(KT_FILES) $(KT_BUILD_FILES)
kmp: $(KMP_LIBS) ## Build the Kotlin multi-platform package
	cd crypto-ffi/bindings && \
	./gradlew $(addprefix core-crypto-kmp:,$(KMP_ARTIFACT_TASKS)) $(KMP_GRADLE_ARGS)

# The JVM library isn't in the deps, which CI hashes before it's built.
kmp-jvm-test-deps := $(RUST_SOURCES) $(KT_FILES) $(KT_BUILD_FILES)

$(STAMPS)/kmp-jvm-test: $(kmp-jvm-test-deps) $(JVM_LIB)
	cd crypto-ffi/bindings && \
	./gradlew core-crypto-kmp:jvmTest --rerun $(KMP_GRADLE_ARGS)
	$(TOUCH_STAMP)
