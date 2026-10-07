# Manually publish release artifacts

If one of the publishing jobs fails due to some temporary error, it might be necessary to publish the release artifacts
for a platform manually to avoid having to restart the whole release process.

## Android / JVM / KMP (Kotlin)

These cannot be published manually. Wire's Maven repository accepts uploads only from CI runs triggered by pushing a
release tag, and never overwrites or deletes a published file.

If `publish-jvm`, `publish-android` or `publish-kmp` fails, re-run the failed jobs of the tag's pipeline run. A release
job is safe to re-run after a partial upload: it accepts files that are already published with identical content, and
uploads the rest. It releases what `prepare-publish` staged earlier in the same run, and staged artifacts are kept for 7
days.

If a release job fails because a file is already published with different content, or the staged artifacts have expired,
that version cannot be completed. Release a new patch version instead.

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
