SHELL := /usr/bin/env bash

# Only build in release mode if explicitly requested by
# setting the `RELEASE` variable to any non-empty value, e.g.
#
#   make wasm RELEASE=1
#
# This will also optimize the Wasm binary.
ifeq ($(RELEASE),)
  CARGO_BUILD_ARGS :=
  XCODE_CONFIG := Debug
  GRADLE_BUILD_TYPE := Debug
  RELEASE_MODE := debug
else
  CARGO_BUILD_ARGS := --release
  XCODE_CONFIG := Release
  GRADLE_BUILD_TYPE := Release
  RELEASE_MODE := release
endif

TARGET_DIR := target/$(RELEASE_MODE)

# Detect host platform for NDK and library extensions
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  PLATFORM_DIR       := linux-x86_64
  LIBRARY_EXTENSION  := so
else ifeq ($(UNAME_S),Darwin)
  PLATFORM_DIR       := darwin-x86_64
  LIBRARY_EXTENSION  := dylib
else
  $(error Unsupported host platform $(UNAME_S))
endif

# Make platform-specific LLVM toolchain available to Android builds.
export PATH := $(PATH):$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(PLATFORM_DIR)/bin

# Directory we store timestamps in
STAMPS := .stamps

# We're writing a timestamp into the file because CI relies on file hashes to
# change when the stamp files are updated.
TOUCH_STAMP = @mkdir -p $(STAMPS) && echo "$$(date)" > $@

RUST_STRIP_FLAGS :=
ifeq ($(RELEASE_MODE),release)
RUST_STRIP_FLAGS := -C strip=symbols
endif
