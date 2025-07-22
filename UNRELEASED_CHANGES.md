# Changelog

## Unreleased

### Features

- hold a file lock on they keystore while executing a transaction ([1abf479](https://github.com/wireapp/core-crypto/commit/1abf4794532b07c7ea04a77354fdbce010bb4a3a))

### Bug Fixes

- don't throw an error when calling proteus_reload_sessions without having called proteus_init ([2ca0907](https://github.com/wireapp/core-crypto/commit/2ca0907334a063853be9e91998c249f2ac1b1476))
- use `HashMap` for in-memory cache [WPB-18762] ([4bc12dc](https://github.com/wireapp/core-crypto/commit/4bc12dc382328cc937854d7b95eabb5f2461bf8a))
- use consistent ids for `ProteusIdentity` ([6b9f1e2](https://github.com/wireapp/core-crypto/commit/6b9f1e20f632802aafc5bec086d3ed93d5c734fe))

### Documentation

- add docs for `ByteArray.toGroupInfo()` ([748082b](https://github.com/wireapp/core-crypto/commit/748082b8d127f4571982d64cb48ebdf7bd4f6364))
- remove unintended code comment showing up in  `index.md` ([7dd028b](https://github.com/wireapp/core-crypto/commit/7dd028b55c575c63c8d917073842c7f5c31dba17))
- update links in `index.md` ([a085ae6](https://github.com/wireapp/core-crypto/commit/a085ae67d1af84c3d00be1e6478c6e5b496f67d3))

### Testing

- add test asserting that transactions are performally serially also across multiple CoreCrypto instances ([d4c6667](https://github.com/wireapp/core-crypto/commit/d4c6667d06d4be7971ab0d0af144587456d7023e))
- update tests according to refactorings for new in-memory cache ([5b15f83](https://github.com/wireapp/core-crypto/commit/5b15f8337f41eaacecf9880d019669f99cb8fb99))
- crypto-ffi: remove now-unused global const IDs ([c0029c7](https://github.com/wireapp/core-crypto/commit/c0029c78777e6178d59d61a3fbeddef186a62366))
- crypto-ffi: do not use same IDs across different tests ([cdf3aa3](https://github.com/wireapp/core-crypto/commit/cdf3aa3c9f98e0a794f63b4e301486f8528dc6e3))

### Other Breaking Changes

- [**breaking**] Revert "refactor!(kotlin): `CoreCryptoContext.exportSecretKey` now returns a newtype" ([2e61956](https://github.com/wireapp/core-crypto/commit/2e6195669a9840c7c4448d61acd6be4906d5dfcb))


