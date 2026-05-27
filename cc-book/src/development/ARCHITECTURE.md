# CoreCrypto Architecture

```mermaid
block-beta

columns 1

block:system
    Kotlin
    Swift
    TSN["TS Native"]
    TSB["TS Browser"]
end

block:uniffi
    UniFFI
    UBRN
end

RUSTFFI["CoreCrypto FFI"]

block:crypto
    CRYPTO["Crypto<br/>MLS • Proteus"]
    E2EI["E2E Identity"]
end

STORAGE["Storage"]
block:database
    Native["SQLite + SQLCipher"]
    Browser["IndexedDB"]
end

classDef highlighted fill:#969,stroke:#333,stroke-width:3px;
class TSB highlighted
class Browser highlighted
```

## CoreCrypto FFI

Allows other programming languages and platforms to embed and interact with `CoreCrypto`

- For iOS and Android, [UniFFI](https://github.com/mozilla/uniffi-rs) is used to produce the relevant Kotlin and Swift
  bindings
- For Typescript we additionally use [UBRN](https://github.com/jhugman/uniffi-bindgen-react-native) to create a WASM
  binary for browser and a native binary for native TS from our UniFFI bindings.

### Data Types

| Rust                    | Swift                              | Kotlin                     | TypeScript                               |
| ----------------------- | ---------------------------------- | -------------------------- | ---------------------------------------- |
| `bool`                  | `Bool`                             | `Boolean`                  | `boolean`                                |
| `u8`                    | `UInt8`                            | `UByte`                    | `number`                                 |
| `u16`                   | `UInt16`                           | `UShort`                   | `number`                                 |
| `u32`                   | `UInt32`                           | `UInt`                     | `number`                                 |
| `u64`                   | `UInt64`                           | `ULong`                    | `number`                                 |
| `i8`                    | `Int8`                             | `Byte`                     | `number`                                 |
| `i16`                   | `Int16`                            | `Short`                    | `number`                                 |
| `i32`                   | `Int32`                            | `Int`                      | `number`                                 |
| `i64`                   | `Int64`                            | `Long`                     | `number`                                 |
| `f32`                   | `Float`                            | `Float`                    | `number`                                 |
| `f64`                   | `Double`                           | `Double`                   | `number`                                 |
| `String` / `&str`       | `String`                           | `String`                   | `string`                                 |
| `std::time::SystemTime` | `Date`                             | `java.time.Instant`        | `Date`                                   |
| `std::time::Duration`   | `TimeInterval`                     | `java.time.Duration`       | `number` (in milliseconds)               |
| `Option<T>`             | `Optional<T>`                      | `Optional<T>`              | `T?`                                     |
| `Vec<T>`                | `Array<T>`                         | `List<T>`                  | `Array<T>`                               |
| `HashMap<String, T>`    | `Dictionary<String, T>`            | `Map<String, T>`           | `Record<string, T>`                      |
| `()`                    | `nil`                              | `null`                     | `null`                                   |
| `Result<T, E>`          | `func placeholder() throws E -> T` | `T placeholder() throws E` | `function placeholder(): T // @throws E` |

## CoreCrypto

CoreCrypto provides a unified abstraction layer over MLS and Proteus. It exposes a simplified interface built around
application-level entities rather than protocol-specific concepts.

## Database

Encrypted Keystore powered by SQLCipher on native platforms. WASM uses an IndexedDB-backed, encrypted store with
AES256-GCM. It provides a persistent data storage layer with encryption at-rest.

### Native (iOS, Android, Ts-Native)

Pretty much everything is handed off to SQLCipher:

- Backing store: Encrypted SQLite database (with [SQLCipher](https://www.zetetic.net/sqlcipher/))
- Encryption: AES256-CBC with per-page IV (provided by [SQLCipher](https://www.zetetic.net/sqlcipher/)).
  - Value-Level Encryption is also possible on the
    [Commercial or Enterprise editions](https://www.zetetic.net/sqlcipher/value-level-encryption/) if we want additional
    security guarantees
- Crypto primitives provider: [OpenSSL](https://www.openssl.org/)
- PRNG provider: [OpenSSL](https://www.openssl.org/)

```mermaid
graph LR
    RS[Rusqlite] --> S[SQLCipher]
    SC{AES-256-CBC}
    S -.->|Encrypts| SC
    SC -.->|Decrypts| S
    SC -->|Stores| SF[File]
```

See [SQLCipher design](https://www.zetetic.net/sqlcipher/design/)

Summary:

- SQLCipher's file page size by default is 4096 bytes
- When using a passphrase (our case), the provided passphrase is derived using PBKDF2-HMAC-SHA512. <br /> The salt of
  this KDF is stored in the 16 first bytes of the file.
  - Note: This cannot be kept as-is on iOS as iOS needs to be able to read the first 16-32 bytes of SQLite databases to
    "magically" guess they are SQLite databases<br /> and to allow reading them from the background. This is very useful
    in the case of background work on iOS such as encrypted data in notifications needing access to the keystore.<br />
- Each page is encrypted or decrypted on-the-fly using AES256-CBC
  - Provided by OpenSSL -`v1.1.1p` as of 29/06/22- in our case, but the crypto provider can be changed to NSS,
    LibTomCrypt or Security.framework
- Each page is written with a unique, random IV (*initialization vector*). This IV is regenerated on each page write.
  This IV is appended at the end of each page.
- Page ciphertexts are authenticated using an authentication tag using HMAC-SHA512. This tag is also appended at the
  each of the page.

### WASM

- Backing store: `IndexedDB` (with the [`idb`](https://crates.io/crates/idb) crate)
- Encryption: AES256-GCM Value-Level-Encryption with random, non-reused 96-bits nonces and embedded authentication tag
  (AAD) of the AEAD
  - Caveat: Primary IDs are not encrypted, as this would compromise lookup and cause whole table <br/> scans. It is thus
    not recommended to store sensitive or identifying data in the primary ID.
  - Caveat: Indexed searches do work, in two steps, an optimistic step fetching an unencrypted record, <br /> and a
    fallback step iterating on all records, decrypting the targeted field and checking it. Worst case it will run a
    whole table scan.
- Crypto primitives provider: RustCrypto - [`aes-gcm`](https://crates.io/crates/aes-gcm) crate
- PRNG provider: [`rand`](https://crates.io/crates/rand) crate with [`getrandom`](https://crates.io/crates/getrandom)
  (uses [Crypto.getRandomValues](https://www.w3.org/TR/WebCryptoAPI/#Crypto-method-getRandomValues) under the hood)

```mermaid
graph LR
    direction LR
    B(Keystore Entities)
    C{AES-256-GCM} -->|Stores| I[IndexedDB]
    B -.->|Encrypts| C
    C -.->|Decrypts| B
```

#### How the value-level encryption works

- Consumers of the library are required to provide 32 bytes, generated by a CSPRNG or a hardware RNG, to be used as an
  AES-256 key <br />
- Entities (i.e. Models in an ORM environment) dictate which fields are encrypted and with which AAD <br /> through
  their implementation of the `Entity` trait.
- By default, the AAD is the primary ID of the IndexedDB collection (i.e Table in a SQL database environment)
- AES256-GCM is used to encrypt the aforementioned fields
  - A random 96-bit (12 bytes) Nonce is generated
  - The AAD is fetched through `Entity::aad()`
  - Together they are fed to [`aes-gcm`](https://crates.io/crates/aes-gcm) to create a ciphertext with embedded
    authentication tag
- The ciphertext is then stored along with its nonce with the following data layout:
  - Cleartext: A buffer of N bytes (`[u8; N]`)
  - Ciphertext: `[12 bytes of nonce..., ...ciphertext]`
- When decrypting, the stored nonce is picked apart from the ciphertext, the AAD is also fetched, then the cleartext is
  <br /> decrypted and returned
- Note: All the fields from all entities are zeroed on drop for security reasons
