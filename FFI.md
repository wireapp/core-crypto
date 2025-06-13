# CoreCrypto FFI Details

## Rust Docs

- [Rust](/core-crypto/main/rust/core_crypto/)

These docs are most useful for Core-Crypto developers working internally, but may be useful for client developers looking for additional insights on implementation.

## Bindings Docs

- [Typescript](/core-crypto/main/typescript)
- [Kotlin](/core-crypto/main/kotlin)
- [Swift](/core-crypto/main/swift)

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
