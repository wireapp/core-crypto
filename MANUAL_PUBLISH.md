# Manually publish release artifacts

If one of the publishing jobs fails due to some temporary error, it might be necessary to publish the release artifacts
for a platform manually to avoid having to restart the whole release process.

## Android / JVM (Kotlin)

### Preparation

- Checkout the release tag
- Open the Core Libraries vault on 1Password and copy the secrets from
  [Maven Central Publishing](https://start.1password.com/open/i?a=FOQLGGWZU5EQXEJO3V3A5HI3DU&v=djjqzfw3nbf5zi5ytli7eg6vza&i=bhy2booptksljmacemcsfqjlui&h=wire.1password.eu)
  and
  [CoreCrypto Sonatype PGP Signing Key](https://start.1password.com/open/i?a=FOQLGGWZU5EQXEJO3V3A5HI3DU&v=djjqzfw3nbf5zi5ytli7eg6vza&i=bpxhdqfderdddblxes4pu4s6ji&h=wire.1password.eu)
  ```
  export ORG_GRADLE_PROJECT_mavenCentralPassword <secret>
  export ORG_GRADLE_PROJECT_mavenCentralUsername <secret>
  export ORG_GRADLE_PROJECT_signingInMemoryKeyId <secret>
  export ORG_GRADLE_PROJECT_signingInMemoryKey <secret>
  export ORG_GRADLE_PROJECT_signingInMemoryKeyPassword <secret>
  ```

### Android

- Download the android.zip from the release on https://github.com/wireapp/core-crypto/releases
- Extract the archive and copy the Android artifacts into the root of the core-crypto project
  ```bash
  cp -r ~/downloads/android/* core-crypto
  ```
- Publish the project
  ```bash
  cd crypto-ffi/bindings
  ./gradlew android:publishAllPublicationsToMavenCentralRepository --no-configuration-cache
  ```

### JVM

- Download the jvm.zip from the release on https://github.com/wireapp/core-crypto/releases
- Extract the archive and copy the JVM artifacts into the root of the core-crypto project
  ```bash
  cp -r ~/downloads/jvm/* core-crypto
  ```
- Publish the project
  ```bash
  cd crypto-ffi/bindings
  ./gradlew jvm:publishAllPublicationsToMavenCentralRepository --no-configuration-cache
  ```

## iOS (Swift)

iOS artifacts aren't distributed through a centralized package manager. If the artifact has been uploaded to the GitHub
release, it is considered to be published.

## NPM (Typescript)

- Download the `wireapp-core-crypto-x.y.z.tgz` from the release on https://github.com/wireapp/core-crypto/releases
- Publish:
  ```bash
  cd crypto-ffi/bindings/js
  bun publish ~/downloads/wireapp-core-crypto-x.y.z.tgz
  ```
