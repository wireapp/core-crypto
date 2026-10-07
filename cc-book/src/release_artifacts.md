# Release Artifacts

Core-Crypto publishes releases to a variety of platforms.

## Typescript

TypeScript releases are published on NPM as separate packages:

- [@wireapp/core-crypto](https://www.npmjs.com/package/@wireapp/core-crypto) for browsers.
- [@wireapp/core-crypto-native](https://www.npmjs.com/package/@wireapp/core-crypto-native) for native javascript
  runtimes.

## Kotlin (JVM / Android / KMP)

Kotlin bindings are published to Wire's Maven repository, <https://maven.wire.com>, in the `com.wire` group:

- `core-crypto-jvm` for the JVM
- `core-crypto-android` for Android
- `core-crypto-kmp` for Kotlin Multiplatform

Add the repository to your build:

```kotlin
repositories {
    maven { url = uri("https://maven.wire.com") }
}
```

or, for Maven:

```xml
<repositories>
    <repository>
        <id>wire</id>
        <url>https://maven.wire.com</url>
    </repository>
</repositories>
```

Earlier releases were published to Maven Central, where they remain; keep `mavenCentral()` among your repositories to
resolve them.

## Swift

Swift bindings are published as a pair of `.xcframework.zip` files on the
[Github release](https://github.com/wireapp/core-crypto/releases/latest).

## Rust

We do _not_ publish releases to [crates.io](https://crates.io/). Instead, if you need to include CC as a dependency, add
it via the repo:

```toml
core-crypto = { version = "10.0.0", tag = "v10.0.0", git = "https://github.com/wireapp/core-crypto" }
```
