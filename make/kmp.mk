#-------------------------------------------------------------------------------
# KMP (Kotlin Multiplatform) builds
#-------------------------------------------------------------------------------

# JVM libraries that only the KMP package ships

# darwin x86_64 build
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

# linux aarch64 build
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

# windows build. Cross-compiled with mingw-w64.
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

# OxiKT packages the libraries make builds in `target`. Debug builds need the host's JVM and
# Android libraries, release builds every JVM and Android library. On macOS, both also need the
# Apple static libraries; elsewhere Kotlin/Native skips the Apple targets. For debug builds, OxiKT
# picks the Android ABIs by the host's architecture, which doesn't always match the one make builds.
KMP_GRADLE_ARGS := $(if $(RELEASE),-PreleaseBuild=true -PbindingsLibrary=$(abspath $(FFI_LIBRARY)),-PandroidAbis=$(ANDROID_TEST_ABI))

# The static library and its linker options, built with the given dynamic library
kmp-apple-files = $(basename $(1)).a $(dir $(1))core_crypto_ffi.native-static-libs
KMP_APPLE_LIBS := $(IOS_DEVICE) $(IOS_SIMULATOR_ARM) $(JVM_DARWIN_LIB)
$(foreach lib,$(KMP_APPLE_LIBS),$(eval $(call kmp-apple-files,$(lib)): $(lib) ;))

# The simulator library is always a release build, but debug builds look for it under `debug`.
KMP_SIMULATOR_FILES := $(subst /release/,/$(RELEASE_MODE)/,$(call kmp-apple-files,$(IOS_SIMULATOR_ARM)))
ifneq ($(RELEASE_MODE),release)
target/aarch64-apple-ios-sim/$(RELEASE_MODE)/%: target/aarch64-apple-ios-sim/release/%
	mkdir -p $(@D) && ln -f $< $@
endif

KMP_JVM_RELEASE_LIBS := $(JVM_DARWIN_LIB) $(JVM_DARWIN_X86_LIB) $(JVM_LINUX_LIB) $(JVM_LINUX_ARM_LIB) $(JVM_WINDOWS_LIB)
KMP_RELEASE_LIBS := $(KMP_JVM_RELEASE_LIBS) $(ANDROID_ARMv7) $(ANDROID_ARMv8) $(ANDROID_X86)
KMP_LIBS := $(if $(RELEASE),$(KMP_RELEASE_LIBS),$(JVM_LIB) $(ANDROID_TEST_LIB)) \
	$(if $(filter Darwin,$(UNAME_S)),$(foreach lib,$(IOS_DEVICE) $(JVM_DARWIN_LIB),$(call kmp-apple-files,$(lib))) \
	$(KMP_SIMULATOR_FILES))

# What the package publishes. Not `assemble`, which also compiles the native tests, and those use
# JVM-only APIs.
KMP_ARTIFACT_TASKS := allMetadataJar jvmJar bundleAndroidMainAar iosArm64MainKlibrary \
	iosSimulatorArm64MainKlibrary macosArm64MainKlibrary

.PHONY: kmp
kmp-deps := $(RUST_SOURCES) $(KT_FILES) $(KT_BUILD_FILES)
kmp: $(KMP_LIBS) $(if $(RELEASE),$(FFI_LIBRARY)) ## Build the Kotlin multi-platform package
	cd crypto-ffi/bindings && \
	./gradlew $(addprefix core-crypto-kmp:,$(KMP_ARTIFACT_TASKS)) $(KMP_GRADLE_ARGS)

# The JVM libraries aren't in the deps, which CI hashes before they're built. Release builds test
# the jar with every JVM library.
kmp-jvm-test-deps := $(RUST_SOURCES) $(KT_FILES) $(KT_BUILD_FILES)

$(STAMPS)/kmp-jvm-test: $(kmp-jvm-test-deps) $(if $(RELEASE),$(KMP_JVM_RELEASE_LIBS) $(FFI_LIBRARY),$(JVM_LIB))
	cd crypto-ffi/bindings && \
	./gradlew core-crypto-kmp:jvmTest --rerun $(KMP_GRADLE_ARGS)
	$(TOUCH_STAMP)
