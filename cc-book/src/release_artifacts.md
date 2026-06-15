# Release Artifacts

Core-Crypto publishes releases to a variety of platforms.

## Typescript

Typescript releases are published [on NPM](https://www.npmjs.com/package/@wireapp/core-crypto).

## JVM / KMP

Java bindings are published [on Sonatype](https://central.sonatype.com/artifact/com.wire/core-crypto-jvm).

## Android

Android bindings are published [on Sonatype](https://central.sonatype.com/artifact/com.wire/core-crypto-android).

## Swift

Swift bindings are published as a pair of `.xcframework.zip` files on the
[Github release](https://github.com/wireapp/core-crypto/releases/latest).

## Rust

We do _not_ publish releases to [crates.io](https://crates.io/). Instead, if you need to include CC as a dependency, add
it via the repo:

```toml
core-crypto = { version = "10.0.0", tag = "v10.0.0", git = "https://github.com/wireapp/core-crypto" }
```
