# Rust Crypto Dependencies

## Cryptographic primitives & spec implementations

| Primitive        | Repository                                                          | Known audits                                                               |
|------------------|---------------------------------------------------------------------|----------------------------------------------------------------------------|
| P256             | [RustCrypto/p256][p256]                                             | N/A                                                                        |
| P384             | [RustCrypto/p384][p384]                                             | N/A                                                                        |
| Curve25519       | [dalek-cryptography/curve25519-dalek][curve25519-dalek]             | N/A                                                                        |
| Ed25519          | [dalek-cryptography/ed25519-dalek][ed25519-dalek]                   | N/A                                                                        |
| X25519           | [dalek-cryptography/x25519-dalek][x25519-dalek]                     | N/A                                                                        |
| SHA2             | [RustCrypto/sha2][sha2]                                             | N/A                                                                        |
| HMAC             | [RustCrypto/hmac][hmac]                                             | N/A                                                                        |
| AES-GCM          | [RustCrypto/aes-gcm][aes-gcm]                                       | [Audit by NCC Group][ncc-group-audit]                                      |
| ChaCha20Poly1305 | [RustCrypto/chacha20poly1305][chacha20poly1305]                     | [Audit by NCC Group][ncc-group-audit]                                      |
| HKDF             | [RustCrypto/hkdf][hkdf]                                             | N/A                                                                        |
| HPKE             | [rozbb/rust-hpke][hpke]                                             | [No formal audits, but Cloudflare reviewed it][hpke-sec]                   |
| KyberDraft00     | [bwesterb/agyle-kyber][kyber]                                       | N/A, but the fork exists because of a [review][kyber-review] by Cloudflare |

## CSPRNG

* We use [rand][rand] in combination with [rand-chacha][rand-chacha] to achieve a proper CSPRNG
    * No audits are known of this crate, but it is the de facto for the Rust ecosystem and is used by pretty much any crate needing a randomness source.
    * Note: We use [getrandom][getrandom] under the hood to retrieve random data. Other than de facto OS entropy sources, we can inject entropy at will
        * On this topic, the entropy sources per platform are detailed [here][getrandom-entropy]

[p256]: https://github.com/RustCrypto/elliptic-curves/tree/master/p256
[p384]: https://github.com/RustCrypto/elliptic-curves/tree/master/p384
[sha2]: https://github.com/RustCrypto/hashes/tree/master/sha2
[hmac]: https://github.com/RustCrypto/MACs/tree/master/hmac
[aes-gcm]: https://github.com/RustCrypto/AEADs/tree/master/aes-gcm
[chacha20poly1305]: https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305
[hkdf]: https://github.com/RustCrypto/KDFs/tree/master/hkdf
[curve25519-dalek]: https://github.com/dalek-cryptography/curve25519-dalek/tree/main/curve25519-dalek
[ed25519-dalek]: https://github.com/dalek-cryptography/ed25519-dalek
[x25519-dalek]: https://github.com/dalek-cryptography/x25519-dalek
[ncc-group-audit]: https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/
[hpke]: https://github.com/rozbb/rust-hpke/tree/unstable-pq-xyber
[hpke-sec]: https://github.com/rozbb/rust-hpke/tree/unstable-pq-xyber#warning
[kyber]: https://github.com/bwesterb/argyle-kyber
[kyber-review]: https://github.com/Argyle-Software/kyber/issues/73
[rand]: https://github.com/rust-random/rand
[rand-chacha]: https://github.com/rust-random/rand/tree/master/rand_chacha
[getrandom]: https://github.com/rust-random/getrandom
[getrandom-entropy]: https://docs.rs/getrandom/latest/getrandom/#supported-targets
