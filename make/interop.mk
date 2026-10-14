#-------------------------------------------------------------------------------
# interop test
#-------------------------------------------------------------------------------

# We're not building the interop binary in release mode, so it's in `target/debug`.
INTEROP_OUT := target/debug/interop

.PHONY: interop-build
interop-build: $(INTEROP_OUT)  ## Build the interop test binary (in debug mode, ignores any `RELEASE` value)

# The interop binary is the native client in the test, so it links all of
# core-crypto, not only the `interop` crate. Its artifact must be rebuilt
# whenever any of that changes, as well as when the `interop` crate does.
interop-build-deps := $(RUST_SOURCES) $(INTEROP_RS_FILES) $(INTEROP_TS_FILES) $(INTEROP_MANIFEST)

$(INTEROP_OUT): $(interop-build-deps)
	cargo build --bin interop

# The iOS interop app, built for the arm64 simulator so that CI can build it once
# and install it on any simulator.
INTEROP_IOS_APP_DIR := interop/src/clients/InteropClient
INTEROP_IOS_APP := $(INTEROP_IOS_APP_DIR)/Products/Applications/InteropClient.app

# The Xcode projects, sources, assets and settings of the app and of the Swift
# wrapper it links. The test targets, docs and the install script aren't part of
# the app. `Preview Content` only holds assets for Xcode's previews, and its path
# contains a space, which make can't handle in a list of prerequisites.
INTEROP_IOS_APP_SOURCES := $(shell fd --type f \
	--exclude 'Preview Content' --exclude TestHost --exclude WireCoreCryptoTests --exclude '*.docc' --exclude '*.sh' \
	. $(INTEROP_IOS_APP_DIR) crypto-ffi/bindings/swift | LC_ALL=C sort)

# The app links the static library, which is built together with
# `$(IOS_SIMULATOR_ARM)`, so that stands in for it here.
interop-ios-app-deps := $(IOS_SIMULATOR_ARM) $(UNIFFI_SWIFT_OUTPUT) $(SWIFT_WRAPPER_GENERATED) $(INTEROP_IOS_APP_SOURCES)

# `ARCHS=arm64` because we only build the Rust library for the arm64 simulator,
# and a Release build would otherwise try to build an x86_64 slice as well.
$(STAMPS)/interop-ios-app: $(interop-ios-app-deps)
	cd $(INTEROP_IOS_APP_DIR) && xcodebuild \
	  -scheme InteropClient \
	  -configuration $(XCODE_CONFIG) \
	  -sdk iphonesimulator \
	  -destination 'generic/platform=iOS Simulator' \
	  ARCHS=arm64 \
	  build install DSTROOT=./Products
	$(TOUCH_STAMP)

.PHONY: interop-ios-app
interop-ios-app: $(STAMPS)/interop-ios-app ## Build the iOS interop app for the simulator (macOS only)

# The Android interop app. CI builds it on Linux but installs it on an arm64
# emulator on macOS, so it bundles the libraries for every Android ABI rather
# than only the host's (see `coreCryptoAndroidBuildAllAbis` in
# `crypto-ffi/bindings/android/build.gradle.kts`).
INTEROP_APK := interop/src/clients/android-interop/build/outputs/apk/$(RELEASE_MODE)/android-interop-$(RELEASE_MODE).apk

# Besides the Kotlin sources and Gradle scripts, the app's manifest and the
# Gradle settings, wrappers and version catalogs of both builds.
INTEROP_ANDROID_APP_SOURCES := $(shell fd --type f \
	. interop/src/clients/android-interop interop/src/clients/gradle crypto-ffi/bindings/gradle | LC_ALL=C sort) \
	interop/src/clients/gradle.properties crypto-ffi/bindings/gradle.properties crypto-ffi/bindings/android/gradle.properties

interop-android-app-deps := $(ANDROID_ARMv7) $(ANDROID_ARMv8) $(ANDROID_X86) $(UNIFFI_ANDROID_OUTPUT) \
	$(KT_FILES) $(KT_GRADLE_FILES) $(INTEROP_ANDROID_APP_SOURCES)

$(INTEROP_APK): $(interop-android-app-deps)
	cd interop/src/clients && \
	./gradlew android-interop:assemble$(GRADLE_BUILD_TYPE) -DcoreCryptoAndroidBuildAllAbis=true

.PHONY: interop-android-app
interop-android-app: $(INTEROP_APK) ## Build the Android interop app, with the libraries for every Android ABI

interop-test-deps := $(INTEROP_OUT) $(BROWSER_OUT) $(ANDROID_TEST_LIB) $(UNIFFI_ANDROID_OUTPUT) $(KT_FILES) $(KT_GRADLE_FILES)
ifeq ($(UNAME_S),Darwin)
interop-test-deps := $(interop-test-deps) $(IOS_SIMULATOR_ARM) $(UNIFFI_SWIFT_OUTPUT) $(SWIFT_FILES)
endif

$(STAMPS)/interop-test: $(interop-test-deps)
	$(SHELL) scripts/run-interop-test.sh $(XCODE_CONFIG)
	$(TOUCH_STAMP)
