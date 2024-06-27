# CoreCrypto FFI Details

## Bindings

* WASM / TypeScript bindings are self-documented in [crypto-ffi/bindings/js/CoreCrypto.ts].
    * Please refer to your IDE of choice's inlay hints or simply check out the `TypeDoc`-generated documentation on [typescript]
    * Naming convention wise, `snake_case` gets translated to the TS idiomatic `camelCase` for methods and `PascalCase` for classes/interfaces
* UniFFI-generated bindings (Swift, Kotlin) share the same characteristics in terms of naming convention translation.
    * The general convention is that the idiomatic Rust `snake_case` gets translated to the language's idiomatic convention. Fortunately, for both Swift and Kotlin, the convention is `camelCase` for methods and `PascalCase` for classes/interfaces.

## Naming conventions table

| Item                | Rust         | Swift        | Kotlin       | TypeScript   |
|---------------------|--------------|--------------|--------------|--------------|
| Methods/Functions   | `snake_case` | `camelCase`  | `camelCase`  | `camelCase`  |
| Variables/Arguments | `snake_case` | `camelCase`  | `camelCase`  | `camelCase`  |
| Classes/Interfaces  | `PascalCase` | `PascalCase` | `PascalCase` | `PascalCase` |


## Types equivalence table

| Rust                    | Swift                              | Kotlin                     | TypeScript                               |
|-------------------------|------------------------------------|----------------------------|------------------------------------------|
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

## Adding new APIs

1. Make your changes wherever applicable.
1. Make sure your new API is available on `MlsCentral`, while respecting encapsulation
    - For example, adding `MlsConversation::hello()` would mean exposing a new `MlsCentral::conversation_hello(conversation_id: ConversationId)`
1. Expose your new API on both `crypto-ffi/src/[generic|wasm].rs`.
1. Add the new APIs respecting the appropriate calling conventions defined above to
    - Kotlin/Android: `crypto-ffi/bindings/jvm/src/main/kotlin/com/wire/crypto/client/[CoreCryptoCentral|E2eiClient|MLSClient].kt`
    - TypeScript/Web: `crypto-ffi/bindings/js/CoreCrypto.ts`
    (Swift/iOS are automatically generated)
1. Add documentation for the new API in the bindings.
1. Add a test for the bindings. This is easily done by extending the existing test suite in `crypto-ffi/bindings/js/test/CoreCrypto.test.js`.
   For example, see [this commit](https://github.com/wireapp/core-crypto/commit/5e9ecf7328b33730f31dfc25aeb168e090a7b1e5).
