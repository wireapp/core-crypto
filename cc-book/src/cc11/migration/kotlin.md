# Migrating to CC 11: Kotlin

See the [common migration guide](../migration-guide.md) for changes that apply to all platforms.

## Maven Repository

The JVM, Android and KMP packages are now published to Wire's Maven repository, <https://maven.wire.com>, instead of
Maven Central. Add `maven { url = uri("https://maven.wire.com") }` to your repositories. Earlier releases remain on
Maven Central.

## Timestamps

Timestamps now use `kotlin.time.Instant` instead of `kotlinx.datetime.Instant`. This affects `X509Identity.notBefore`
and `X509Identity.notAfter`.

## Database Salt on iOS

On the iOS targets, the database salt has moved from the keychain into a file next to the database. See the
[Swift migration guide](swift.md#database-path-and-salt) for what this means for existing clients.
