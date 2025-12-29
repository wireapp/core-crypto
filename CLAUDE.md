# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Wire CoreCrypto is a cross-platform cryptography library that provides MLS (Messaging Layer Security) and Proteus protocol implementations with an encrypted keystore. The project uses Rust as the core language and generates bindings for iOS (Swift), Android/JVM (Kotlin), and Web (TypeScript/WASM).

## Architecture

### Core Components

The repository is structured as a Rust workspace with the following key crates:

- **crypto**: Core library (`core_crypto`) - Abstracts MLS & Proteus protocols in a unified API around a `Central` concept (see `MlsCentral`). Provides high-level operations for clients, conversations, and members while hiding protocol specifics.

- **keystore**: Encrypted storage layer using SQLCipher on native platforms and AES-GCM-256 encrypted IndexedDB on WASM. Implements persistence for MLS and Proteus keying material.

- **mls-provider**: OpenMLS integration layer - implements `OpenMLSCryptoProvider` trait to connect OpenMLS with our keystore and RustCrypto.

- **crypto-ffi**: FFI bindings layer using UniFFI for iOS/Android and wasm-bindgen for Web/WASM.

- **e2e-identity**: End-to-end identity (E2EI) implementation for X.509 certificate-based authentication.

- **crypto-macros**: Procedural macros for the crypto crate.

- **test-wire-server**: Test infrastructure for E2EI testing.

- **interop**: Interoperability testing between platforms.

- **keystore-dump**: Utility for inspecting keystore contents.

- **decode**: Decoding utilities.

- **obfuscate**: Code obfuscation utilities.

### Key Concepts

- **Central**: Entry point (`MlsCentral`) that holds runtime state, manages the local client, and orchestrates conversation operations.
- **Client**: The local user device with ability to produce keying material.
- **Member**: Remote clients in conversations without local keying material generation.
- **Conversation**: Group chat abstraction (MLS group or Proteus sessions).

### FFI Architecture

- **iOS/Android**: UniFFI generates idiomatic Swift/Kotlin bindings from Rust
- **Web/WASM**: wasm-bindgen + wasm-pack for TypeScript bindings
- **Naming conventions**: Rust `snake_case` becomes `camelCase` in all target languages
- **Type mappings**: See `docs/FFI.md` for complete type equivalence table

## Common Commands

### Building

```bash
# Build for specific platforms
make jvm              # Build JVM bindings (macOS/Linux auto-detected)
make android          # Build all Android targets (ARMv7, ARMv8, x86_64)
make ios              # Build iOS targets (device + simulator)
make ios-create-xcframework  # Create iOS XCFramework
make ts               # Build TypeScript/WASM bindings
make wasm             # Alias for 'ts'

# Build all platforms and docs
make all

# Build bindings without building targets
make bindings         # Generate all bindings (platform-specific)
make bindings-swift   # Generate Swift bindings (macOS only)
make bindings-kotlin  # Generate Kotlin bindings (Android + JVM)

# Build just the FFI library and bindgen tool
make ffi-library
make uniffi-bindgen
```

### Testing

```bash
# Rust tests
cargo nextest run                          # Run all tests except E2EI
cargo nextest run --features test-all-cipher  # Test all cipher suites (slow)

# Platform-specific tests
make jvm-test         # Kotlin/JVM tests
make android-test     # Android tests
make ts-test          # TypeScript/WASM tests

# Run specific TypeScript test
make ts-test TEST="test name pattern"

# E2EI tests (requires Docker/Podman)
bash scripts/run-e2ei-tests.sh           # All E2EI tests
bash scripts/run-e2ei-tests.sh alg::p256 # Specific test

# WASM-specific Rust tests
wasm-pack test --headless --chrome ./keystore
```

### Formatting & Linting

```bash
# Format all code
make fmt              # Format all languages
make rust-fmt         # Rust only
make swift-fmt        # Swift only
make kotlin-fmt       # Kotlin only
make ts-fmt           # TypeScript only

# Lint/check all code
make check            # Check all languages
make rust-check       # Rust clippy + check
make swift-check      # Swift format + swiftlint
make kotlin-check     # ktlint
make ts-check         # eslint + tsc
```

### Documentation

```bash
make docs                # Generate all docs
make docs-rust-generic   # Rust docs (host platform)
make docs-rust-wasm      # Rust docs (wasm32 target)
make docs-kotlin         # Kotlin/JVM docs
make docs-ts             # TypeScript docs
make docs-swift          # Swift docs (macOS only)
```

### Benchmarks

```bash
# Run specific benchmark
cargo bench --bench=commit -- --quick

# Available benchmarks (see crypto/Cargo.toml):
# - key_package, proposal, commit, encryption, create_group, transaction
```

### Other

```bash
make clean            # Clean build artifacts
make help             # Show all available targets
make interop-build    # Build interop test binary
```

## Development Workflow

### Environment Setup

1. Install Rust via rustup: <https://rustup.rs/>
2. Install nextest: `cargo install --locked cargo-nextest`
3. Install pre-commit hooks: `pre-commit install`
4. Ensure git is configured to sign commits

### Platform-Specific Setup

**JVM**:
- Install SDKMAN: `curl -s "https://get.sdkman.io" | bash`
- Install Java 17: `sdk install java 17.0.17-tem`
- Install Kotlin: `sdk install kotlin`

**Android**:
- Install Android SDK and Build-Tools (API 30+)
- Set `ANDROID_NDK_HOME` environment variable
- Install targets: `rustup target add x86_64-linux-android aarch64-linux-android armv7-linux-androideabi`
- On macOS: `export ANDROID_SDK_ROOT=~/Android/Sdk`

**iOS** (macOS only):
- Install Xcode and command-line tools
- Install targets: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`
- Install swift-format and swiftlint for linting

**WASM**:
- Install wasm-pack: `cargo install --locked wasm-pack`
- Install target: `rustup target add wasm32-unknown-unknown`
- Install Bun: <https://bun.sh/>
- Install node.js (recommended: Volta)
- Install wasm-bindgen-cli: `cargo install wasm-bindgen-cli`
- Install chromedriver: `bunx @puppeteer/browsers install --path ~/bin chrome-headless-shell chromedriver`

### Git Workflow

- Main branch: `main` (everyday development)
- Always rebase on `main` - no merge commits
- Use conventional commits (picked up by changelog generator)
- Sign all commits and tags
- Include JIRA ticket IDs in PR title or commits: `[TICKET_ID]`
- Release branches: `release/<series>` (e.g., `release/1.x`)
  - Created lazily, only when fixes are needed for a specific series
  - Branch off from first major release tag
  - Never merged to main

### Release Process

1. Create branch: `git checkout -b prepare-release/X.Y.Z`
2. Update versions: `sh scripts/update-versions.sh X.Y.Z`
3. Generate changelog: `git cliff --bump --unreleased` and add to `CHANGELOG.md`
4. Update `docs/index.md` with new version table row
5. Create PR, get reviewed, merge to main
6. Create signed tag: `git tag -s vX.Y.Z`
7. Push tag: `git push origin tag vX.Y.Z`
8. Create GitHub release with changelog section

### Pre-commit Hooks

The repository uses pre-commit framework. After installing (`pip install pre-commit`), run `pre-commit install` to set up hooks automatically.

### Important Notes

- **nextest configuration**: By default, `cargo nextest run` excludes `wire-e2e-identity` package (requires special setup via `scripts/run-e2ei-tests.sh`)
- **Release builds**: Set `RELEASE=1` for release mode (e.g., `make wasm RELEASE=1`)
- **TypeScript logging**: Use `CC_TEST_LOG_LEVEL` environment variable (1=browser logs, 2=browser+CoreCrypto logs)
- **E2EI tests**: Require Docker/Podman and set `TEST_IDP` to `keycloak` or `authelia`
- **Profile settings**: Release profile uses `codegen-units=1`, `lto=true`, `opt-level="s"`, and `strip=false` (UniFFI requirement)

## Testing Considerations

- E2EI tests require container runtime (Docker/Podman) to be running
- Manual E2EI test invocation requires starting `test-wire-server` first and setting `TEST_WIRE_SERVER_ADDR`
- WASM keystore tests can be run with `wasm-pack test --headless --chrome ./keystore`
- Android requires NDK environment variable set (`ANDROID_NDK_HOME`)
