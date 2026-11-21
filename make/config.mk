SHELL := /usr/bin/env bash

# Only build in release mode if explicitly requested by
# setting the `RELEASE` variable to any non-empty value, e.g.
#
#   make wasm RELEASE=1
#
# This will also optimize the Wasm binary.
ifeq ($(RELEASE),)
  CARGO_BUILD_ARGS :=
  UBRN_PROFILE := debug
  XCODE_CONFIG := Debug
  GRADLE_BUILD_TYPE := Debug
  RELEASE_MODE := debug
else
  CARGO_BUILD_ARGS := --release
  UBRN_PROFILE := release-small
  XCODE_CONFIG := Release
  GRADLE_BUILD_TYPE := Release
  RELEASE_MODE := release
endif

UBRN_BUILD_ARGS := --profile $(UBRN_PROFILE)

NATIVE_CARGO_BUILD_ARGS := $(CARGO_BUILD_ARGS) --features cancellable-transactions
DARWIN_CARGO_BUILD_ARGS := $(CARGO_BUILD_ARGS) --features cancellable-transactions,cross-process-lock

TARGET_DIR := target/$(RELEASE_MODE)

# Detect host platform for NDK and library extensions
UNAME_S := $(shell uname -s)
# Git Bash and MSYS2 report e.g. `MINGW64_NT-10.0-26200` or `MSYS_NT-10.0-26200`. Windows also
# sets `OS=Windows_NT`, which catches other shells whose `uname` reports something else.
ifneq ($(filter MINGW% MSYS%,$(UNAME_S))$(filter Windows_NT,$(OS)),)
  UNAME_S := Windows
endif

# Windows doesn't prefix library names with `lib`, and executables end in `.exe`.
LIBRARY_PREFIX := lib
EXE_SUFFIX :=
ifeq ($(UNAME_S),Linux)
  PLATFORM_DIR       := linux-x86_64
  LIBRARY_EXTENSION  := so
else ifeq ($(UNAME_S),Darwin)
  PLATFORM_DIR       := darwin-x86_64
  LIBRARY_EXTENSION  := dylib
else ifeq ($(UNAME_S),Windows)
  # Only the JVM library is supported on Windows hosts; there's no Android NDK `PLATFORM_DIR`.
  LIBRARY_PREFIX     :=
  LIBRARY_EXTENSION  := dll
  EXE_SUFFIX         := .exe
else
  $(error Unsupported host platform $(UNAME_S))
endif

# Make platform-specific LLVM toolchain available to Android builds.
ifneq ($(PLATFORM_DIR),)
export PATH := $(PATH):$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(PLATFORM_DIR)/bin
endif

# Directory we store timestamps in
STAMPS := .stamps

# We're writing a timestamp into the file because CI relies on file hashes to
# change when the stamp files are updated.
TOUCH_STAMP = @mkdir -p $(STAMPS) && echo "$$(date)" > $@

RUST_STRIP_FLAGS :=
ifeq ($(RELEASE_MODE),release)
RUST_STRIP_FLAGS := -C strip=symbols
endif
