# Obfuscate

Defines an `Obfuscate` trait with implementations for external types and a wrapper type for usage during debug logging.
Used by `#[sensitive]` fields of structs deriving `crypto_macros::Debug`.

## Cargo Features

No features are included in the default set.

- `openmls`: implements `Obfuscate` for some openmls types.
