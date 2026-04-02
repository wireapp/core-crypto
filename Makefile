# Makefile: Always run Cargo steps, but only re-run downstream generators when inputs change

.PHONY: help
# Parse the comment starting with a double ## next to a target as the target description
# in the help message
help: ## Show this help message
	@grep -E '^[a-zA-Z0-9_.-]+:.*?## ' $(MAKEFILE_LIST) | \
		sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

# Default goal
.DEFAULT_GOAL := local

include make/config.mk
include make/sources.mk
include make/ffi.mk
include make/ios.mk
include make/android.mk
include make/jvm.mk
include make/ts.mk
include make/interop.mk
include make/docs.mk
include make/fmt.mk

#-------------------------------------------------------------------------------
# Aggregate targets
#-------------------------------------------------------------------------------

.PHONY: ts wasm bindings local all clean
ts: $(BROWSER_OUT) ## Build all TypeScript wrappers
wasm: ts-browser  ## Alias for ts-browser
bindings: bindings-kotlin $(if $(filter Darwin,$(UNAME_S)),bindings-swift) ts ## Generate all bindings
local: bindings ts-fmt ## Generate and format all bindings
all: android wasm jvm $(if $(filter Darwin,$(UNAME_S)),ios) docs ## Generate bindings for all platforms (android, iOS, wasm) and generate docs
clean: ts-clean ## Run cargo clean and the ts-clean target, remove all stamps
	cargo clean
	rm -rf $(STAMPS)

#-------------------------------------------------------------------------------
# Lazy targets
#-------------------------------------------------------------------------------

# By default, test targets always re-run (the stamp file is deleted first so
# Make sees the target as dirty). Set LAZY_MAKE=1 to skip a test target when
# its stamp file is still fresh — useful for local iteration when you know the
# inputs haven't changed.
LAZY_TARGETS := jvm-test kmp-jvm-test ts-browser-test ts-native-test ts-test android-test ios-test interop-test jvm-bench

ts-browser-test: ## Run browser TypeScript wrapper tests via wdio and bun/wasm. Optionally pass TEST=<test> to filter by test name.
ts-native-test: ## Run native TypeScript wrapper tests via bun/napi. Optionally pass TEST=<test> to filter by test name.
ts-test: ## Run all TypeScript wrapper tests. Optionally pass TEST=<test> to filter by test name.
kmp-jvm-test: ## Run Kotlin multi-platform tests on JVM
jvm-test: ## Run Kotlin tests on JVM
jvm-bench: ## Run the JVM benchmarks
android-test: ## Run Kotlin tests on Android
ios-test: ## Run Swift tests on iOS (macOS only)
interop-test: ## Run e2e interop test

ifeq ($(LAZY_MAKE),)

.PHONY: $(LAZY_TARGETS)
$(LAZY_TARGETS):
	@rm -f $(STAMPS)/$@
	@$(MAKE) $(STAMPS)/$@

else
$(LAZY_TARGETS): %: $(STAMPS)/%

endif
