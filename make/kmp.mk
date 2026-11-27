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

# OxiKT's bindgen. Gradle would build it into its build directory, which a clean build or CI
# doesn't keep. Like uniffi-bindgen, it only depends on the version.
GET_OXIKT_VERSION = yq -e -r '.versions.oxikt' crypto-ffi/bindings/gradle/libs.versions.toml
OXIKT_VERSION_FILE := $(STAMPS)/oxikt-version

# Version file: only rewrite if version changed
$(OXIKT_VERSION_FILE): crypto-ffi/bindings/gradle/libs.versions.toml
	current_version="$$( $(GET_OXIKT_VERSION) )" || { echo "Couldn't read the OxiKT version from libs.versions.toml" >&2; exit 1; }; \
	if [ ! -f $@ ] || [ "$$(cat $@)" != "$$current_version" ]; then \
		mkdir -p $(STAMPS); \
		echo "$$current_version" > $@; \
	fi

OXIKT_BINDGEN := target/oxikt/bin/uniffi-bindgen-kotlin-multiplatform
oxikt-bindgen-deps := $(OXIKT_VERSION_FILE)
$(OXIKT_BINDGEN): $(oxikt-bindgen-deps)
	cargo install --locked --force --root target/oxikt \
		--git https://github.com/UbiqueInnovation/oxikt.git --tag v$$(cat $(OXIKT_VERSION_FILE)) \
		--bin uniffi-bindgen-kotlin-multiplatform uniffi_bindgen_kotlin_multiplatform

.PHONY: oxikt-bindgen
oxikt-bindgen: $(OXIKT_BINDGEN) ## Build OxiKT's bindgen binary

# OxiKT packages the libraries make builds in `target`. Debug builds need the host's JVM and
# Android libraries, release builds every JVM and Android library. On macOS, both also need the
# Apple static libraries; elsewhere Kotlin/Native skips the Apple targets. For debug builds, OxiKT
# picks the Android ABIs by the host's architecture, which doesn't always match the one make builds.
KMP_GRADLE_ARGS := -Pbindgen=$(abspath $(OXIKT_BINDGEN)) \
	$(if $(RELEASE),-PreleaseBuild=true -PbindingsLibrary=$(abspath $(FFI_LIBRARY)),-PandroidAbis=$(ANDROID_TEST_ABI))

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

# What the package publishes. Not `assemble`, which also links the native test executables.
KMP_ARTIFACT_TASKS := allMetadataJar jvmJar bundleAndroidMainAar iosArm64MainKlibrary \
	iosSimulatorArm64MainKlibrary macosArm64MainKlibrary

.PHONY: kmp
kmp-deps := $(RUST_SOURCES) $(KT_FILES) $(KT_BUILD_FILES)
kmp: $(KMP_LIBS) $(if $(RELEASE),$(FFI_LIBRARY)) | $(OXIKT_BINDGEN) ## Build the Kotlin multi-platform package
	cd crypto-ffi/bindings && \
	./gradlew $(addprefix core-crypto-kmp:,$(KMP_ARTIFACT_TASKS)) $(KMP_GRADLE_ARGS)

# The JVM libraries aren't in the deps, which CI hashes before they're built. Release builds test
# the jar with every JVM library.
kmp-jvm-test-deps := $(RUST_SOURCES) $(KT_FILES) $(KT_BUILD_FILES)

$(STAMPS)/kmp-jvm-test: $(kmp-jvm-test-deps) $(if $(RELEASE),$(KMP_JVM_RELEASE_LIBS) $(FFI_LIBRARY),$(JVM_LIB)) \
	| $(OXIKT_BINDGEN)
	cd crypto-ffi/bindings && \
	./gradlew core-crypto-kmp:jvmTest --rerun $(KMP_GRADLE_ARGS)
	$(TOUCH_STAMP)

# Kotlin/Native runs a test executable on the simulator by itself, but opening a database on iOS
# uses the keychain, which only apps can access. So the script runs it inside an app. Like the
# Swift tests, it uses the simulator library, which is always a release build.
KMP_IOS_TEST_EXECUTABLE := crypto-ffi/bindings/kmp/build/bin/iosSimulatorArm64/debugTest/test.kexe
kmp-ios-test-deps := $(RUST_SOURCES) $(KT_FILES) $(KT_BUILD_FILES) scripts/run-kmp-ios-tests.sh \
	$(wildcard crypto-ffi/bindings/kmp/ios-test-host/*)

$(STAMPS)/kmp-ios-test: $(kmp-ios-test-deps) $(KMP_SIMULATOR_FILES) $(if $(RELEASE),$(FFI_LIBRARY),$(JVM_LIB)) \
	| $(OXIKT_BINDGEN)
	cd crypto-ffi/bindings && \
	./gradlew core-crypto-kmp:linkDebugTestIosSimulatorArm64 $(KMP_GRADLE_ARGS)
	$(SHELL) scripts/run-kmp-ios-tests.sh $(KMP_IOS_TEST_EXECUTABLE)
	$(TOUCH_STAMP)
