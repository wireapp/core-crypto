#-------------------------------------------------------------------------------
# interop test
#-------------------------------------------------------------------------------

# We're not building the interop binary in release mode, so it's in `target/debug`.
INTEROP_OUT := target/debug/interop

.PHONY: interop-build
interop-build: $(INTEROP_OUT)  ## Build the interop test binary (in debug mode, ignores any `RELEASE` value)

interop-build-deps := $(INTEROP_SOURCES)

$(INTEROP_OUT): $(interop-build-deps)
	cargo build --bin interop

interop-test-deps := $(INTEROP_OUT) $(BROWSER_OUT) $(ANDROID_TEST_LIB) $(UNIFFI_ANDROID_OUTPUT) $(KT_FILES) $(KT_GRADLE_FILES)
ifeq ($(UNAME_S),Darwin)
interop-test-deps := $(interop-test-deps) $(IOS_SIMULATOR_ARM) $(UNIFFI_SWIFT_OUTPUT) $(SWIFT_FILES)
endif

$(STAMPS)/interop-test: $(interop-test-deps)
	$(SHELL) scripts/run-interop-test.sh $(XCODE_CONFIG)
	$(TOUCH_STAMP)
