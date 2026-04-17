#-------------------------------------------------------------------------------
# iOS builds
#-------------------------------------------------------------------------------

ios-device-deps := $(RUST_SOURCES)
IOS_DEVICE := target/aarch64-apple-ios/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
$(IOS_DEVICE): $(ios-device-deps)
	IPHONEOS_DEPLOYMENT_TARGET=16.4 \
	cargo rustc --locked \
	  --target aarch64-apple-ios \
	  --crate-type=cdylib \
	  --crate-type=staticlib \
	  --package core-crypto-ffi \
	  $(CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)

.PHONY: ios-device
ios-device: $(IOS_DEVICE) ## Build core-crypto-ffi for aarch64-apple-ios for iOS 16.4 (macOS only)

IOS_SIMULATOR_ARM := target/aarch64-apple-ios-sim/$(RELEASE_MODE)/libcore_crypto_ffi.$(LIBRARY_EXTENSION)
ios-simulator-arm-deps := $(RUST_SOURCES)
$(IOS_SIMULATOR_ARM): $(ios-simulator-arm-deps)
	CRATE_CC_NO_DEFAULTS=1 \
	TARGET_CFLAGS="--target=arm64-apple-ios16.0.0-simulator \
	-mios-simulator-version-min=16.4 \
	-isysroot $$(xcrun --show-sdk-path --sdk iphonesimulator)" \
	cargo rustc --locked \
	  --target aarch64-apple-ios-sim \
	  --crate-type=cdylib \
	  --crate-type=staticlib \
	  --package core-crypto-ffi \
	  $(CARGO_BUILD_ARGS) -- $(RUST_STRIP_FLAGS)

.PHONY: ios-simulator-arm
ios-simulator-arm: $(IOS_SIMULATOR_ARM) ## Build core-crypto-ffi for aarch64-apple-ios-sim, iOS 16.4 (macOS only)

.PHONY: ios
ios: ios-device ios-simulator-arm

# Build XCFramework (macOS only)

ios-create-xcframework-deps := $(IOS_DEVICE) $(IOS_SIMULATOR_ARM) $(UNIFFI_SWIFT_OUTPUT)
$(STAMPS)/ios-create-xcframework: $(ios-create-xcframework-deps)
	$(SHELL) scripts/build-xcframework.sh
	$(TOUCH_STAMP)

.PHONY: ios-create-xcframework
ios-create-xcframework: $(STAMPS)/ios-create-xcframework ## Build the XCode framework (macOS only)

ios-test-deps := $(IOS_SIMULATOR_ARM) $(UNIFFI_SWIFT_OUTPUT) $(SWIFT_FILES)

$(STAMPS)/ios-test: $(ios-test-deps)
	$(SHELL) scripts/run-ios-tests.sh $(XCODE_CONFIG)
	$(TOUCH_STAMP)
