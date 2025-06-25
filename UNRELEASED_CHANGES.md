# Changelog

## Unreleased

### Features

- [**breaking**] crypto-ffi: remove deleteKeypackages ([4c5def3](https://github.com/wireapp/core-crypto/commit/4c5def3f23f3c2e8d9961108ab0827aa7634e2f2))
- introduce HistoryObserver ([43ceb73](https://github.com/wireapp/core-crypto/commit/43ceb7371dfc5f2d46f48c9413dd9f00d2d78e60))
- [**breaking**] crypto: remove e2ei_dump_pki_env and related code ([7927ebb](https://github.com/wireapp/core-crypto/commit/7927ebbed5670be4db316d641bf79a1cfc0611b1))
- [**breaking**] crypto-ffi: remove e2eiDumpPKIEnv and related functions ([b444f13](https://github.com/wireapp/core-crypto/commit/b444f1301982c9dd0aaa44c36c8c3008dd2e7c8b))
- introduce `Metabuilder` ([f556fc7](https://github.com/wireapp/core-crypto/commit/f556fc7001b141323a54203e0695d9e3db2f2fd1))
- support instantiating sessions with mixed credential types ([c8471b2](https://github.com/wireapp/core-crypto/commit/c8471b221eb2c4d6b402bd91569be8ec91ef4290))
- allow session instantiation with test chain and basic credentials ([c700f04](https://github.com/wireapp/core-crypto/commit/c700f042c406d1cdffbbfb1f7824d0c464436468))
- add all required abstactions ([a59c587](https://github.com/wireapp/core-crypto/commit/a59c5876c2d5038151cebbe7212e949a19aa076a))
- [**breaking**] crypto-ffi: remove wasmFilePath ([92e6dad](https://github.com/wireapp/core-crypto/commit/92e6dada9357494b1786e79667e1ab84715bdadc))
- [**breaking**] crypto-ffi: bindings: remove getCredentialInUse ([81a75a8](https://github.com/wireapp/core-crypto/commit/81a75a8b9d270aafaea3441d9c965d2c1f265430))
- crypto: remove generate_raw_keypairs ([1ea2b76](https://github.com/wireapp/core-crypto/commit/1ea2b76825b9799c17a4670d57067e3ef8744552))
- [**breaking**] crypto-ffi: remove mls_generate_keypairs ([5d5cdc1](https://github.com/wireapp/core-crypto/commit/5d5cdc1b3272706ee4ca6556fe1c338ab8ecd142))
- [**breaking**] crypto-ffi: bindings: remove mlsGenerateKeypairs ([ad9a6b8](https://github.com/wireapp/core-crypto/commit/ad9a6b861723f9fe534bcb622013f27df3d53cbd))
- [**breaking**] crypto: remove init_with_external_client_id ([625cbec](https://github.com/wireapp/core-crypto/commit/625cbec18002fc85e72ddbd29848c49a5ca6aabd))
- [**breaking**] crypto-ffi: remove mls_init_with_client_id ([40bbbeb](https://github.com/wireapp/core-crypto/commit/40bbbeb480d68cc154870e6869eb92e52e3911a1))
- [**breaking**] crypto-ffi: bindings: remove mlsInitWithClientId ([10a80ca](https://github.com/wireapp/core-crypto/commit/10a80ca58e2149d60d648ddaeb1db3e8c96009fe))
- add `remove_guarded()` ([6733dad](https://github.com/wireapp/core-crypto/commit/6733dad03219a0b4635db7ec918ef760167317d6))
- add `update_guarded_with()` ([8d98ef2](https://github.com/wireapp/core-crypto/commit/8d98ef20fa89c4b7400f99ac1a20e9a7ac59eaf1))
- add `advance_epoch()` API ([f2c2592](https://github.com/wireapp/core-crypto/commit/f2c2592c5779aa9fbf3bea0b72f8e3f02cc3ffb7))

### Bug Fixes

- building android bindings on a mac ([67125cd](https://github.com/wireapp/core-crypto/commit/67125cd257e5f4ca960f8be81e3e15f467011a9a))
- unreleased changes generation had an extra token ([bc56760](https://github.com/wireapp/core-crypto/commit/bc567602ae772302562073e2fb93969ba29ab433))
- crypto-ffi: fix field names in X509Identity on wasm ([6481d8c](https://github.com/wireapp/core-crypto/commit/6481d8c9e4b32611096cbed4f3281b0127ca3070))
- initWasm was being called with the wrong property field. ([ca52dbf](https://github.com/wireapp/core-crypto/commit/ca52dbf659c88ec02c078fdf3e36420bff5d5c3d))
- allow registering epoch observer before calling mls_init ([0cad9a3](https://github.com/wireapp/core-crypto/commit/0cad9a35c5e27dffbaeced066b1e61105400a09e))

### Documentation

- include hyperlink to commit in git cliff output ([6e209f5](https://github.com/wireapp/core-crypto/commit/6e209f512679acb68fad8f3b932b02b5b93ee7e7))
- publish unreleased changes to github pages ([6c33a70](https://github.com/wireapp/core-crypto/commit/6c33a709b2ed5f1b45c7291f5bbb6cc13ed9abf2))
- add internal links to high-level documents ([0ca52eb](https://github.com/wireapp/core-crypto/commit/0ca52ebe5f2fb0c459bb7594cc6c7b8eb741f6df))
- simplify docs directory structure ([e9a7c2f](https://github.com/wireapp/core-crypto/commit/e9a7c2f5faa848d07392d29b1538aaa27ea76104))
- eliminate fake docs module / submodules ([a459167](https://github.com/wireapp/core-crypto/commit/a459167bd52a4b19cbe982a7bb78a1a0704e65f4))

### Testing

- remove leaf node validation tests [WPB-18083] ([c2ae76d](https://github.com/wireapp/core-crypto/commit/c2ae76d67ef4878d099fb11b27a4987bf3ace687))
- fix: `TestContext::sessions_x509()` should always create x509 sessions ([49ee4e6](https://github.com/wireapp/core-crypto/commit/49ee4e64210ede5054e5cd9ebd86d6ca6c6ac406))
- add test handling self-commit after failed transaction [WPB-17464] ([01a6d46](https://github.com/wireapp/core-crypto/commit/01a6d4638c2b88d5b09e80171075cc37688437b4))

### Other Breaking Changes

- [**breaking**] crypto-ffi: tell wasm-bindgen to output files into a separate dir ([e34b944](https://github.com/wireapp/core-crypto/commit/e34b944694813234dd72cd4a6ed5bcbfa2bf4a70))
- [**breaking**] eliminate certain wasm-specific discrepancies from core-crypto-ffi ([1143d11](https://github.com/wireapp/core-crypto/commit/1143d1105e93fb440c7d89f90598cabd3ee3f4be))


