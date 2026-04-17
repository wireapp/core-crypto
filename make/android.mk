#-------------------------------------------------------------------------------
# Android builds
#-------------------------------------------------------------------------------

# Check NDK env
.PHONY: android-env
android-env:
	@if [ -z "$(ANDROID_NDK_HOME)" ]; then \
	  echo "ERROR: set ANDROID_NDK_HOME"; exit 1; \
	fi
	@ndk_version=$$(perl -ne 's/Pkg\.Revision = // and print' $(ANDROID_NDK_HOME)/source.properties) && \
		echo "Using Android NDK $${ndk_version} at $(ANDROID_NDK_HOME)";

ANDROID_ARMv7 := target/armv7-linux-androideabi/$(RELEASE_MODE)/libcore_crypto_ffi.so
android-armv7-deps := $(RUST_SOURCES)
$(ANDROID_ARMv7): $(android-armv7-deps)
	$(MAKE) android-env;
	cargo rustc --locked \
	  --target armv7-linux-androideabi \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)

.PHONY: android-armv7
android-armv7: $(ANDROID_ARMv7) ## Build core-crypto-ffi for armv7-linux-androideabi

ANDROID_ARMv8 := target/aarch64-linux-android/$(RELEASE_MODE)/libcore_crypto_ffi.so
android-armv8-deps := $(RUST_SOURCES)
$(ANDROID_ARMv8): $(android-armv8-deps)
	$(MAKE) android-env;
	cargo rustc --locked \
	  --target aarch64-linux-android \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)

.PHONY: android-armv8
android-armv8: $(ANDROID_ARMv8) ## Build core-crypto-ffi for aarch64-linux-android

ANDROID_X86 := target/x86_64-linux-android/$(RELEASE_MODE)/libcore_crypto_ffi.so
android-x86-deps := $(RUST_SOURCES)
$(ANDROID_X86): $(android-x86-deps)
	$(MAKE) android-env;
	# Link clang_rt.builtins statically for x86_64 Android
	cargo rustc --locked \
	  --target x86_64-linux-android \
	  --package core-crypto-ffi \
	  --crate-type=cdylib --crate-type=staticlib \
	  $(CARGO_BUILD_ARGS) -- \
	  $(RUST_STRIP_FLAGS) \
	  -l static=clang_rt.builtins-x86_64-android \
	  -L $$($(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(PLATFORM_DIR)/bin/clang --print-resource-dir)/lib/linux

.PHONY: android-x86
android-x86: $(ANDROID_X86) ## Build core-crypto-ffi for x86_64-linux-android

.PHONY: android
android-deps := $(ANDROID_ARMv7) $(ANDROID_ARMv8) $(ANDROID_X86) $(UNIFFI_ANDROID_OUTPUT)
android: $(android-deps) ## Build all Android targets
	cd crypto-ffi/bindings && \
	./gradlew android:assemble$(GRADLE_BUILD_TYPE)

ifeq ($(UNAME_S),Linux)
ANDROID_TEST_LIB := $(ANDROID_X86)
android-test-lib-deps := $(android-x86-deps)
android-test-lib: android-x86 ## Build core-crypto-ffi for Android (automatically select the target based on the host machine)
else ifeq ($(UNAME_S),Darwin)
ANDROID_TEST_LIB := $(ANDROID_ARMv8)
android-test-lib-deps := $(android-armv8-deps)
android-test-lib: android-armv8
else
$(error Unsupported host platform for android-test-lib: $(UNAME_S))
endif

android-test-deps := $(ANDROID_TEST_LIB) $(UNIFFI_ANDROID_OUTPUT) $(KT_FILES)

$(STAMPS)/android-test: $(android-test-deps)
	$(SHELL) scripts/run-android-tests.sh
	$(TOUCH_STAMP)
