# graviola vs aws-lc-rs vs RustCrypto (WPB-29267)

PR #2670 moves part of our MLS crypto provider from RustCrypto to [graviola](https://github.com/ctz/graviola), with a
runtime CPU check and RustCrypto as the fallback. This spike asks how that compares with
[aws-lc-rs](https://github.com/aws/aws-lc-rs), and which libraries we should use: graviola with a RustCrypto fallback,
aws-lc-rs with the same fallback, or a chain of all three.

## Recommendation

Either library makes ciphersuite 2 (P-256), one of our two defaults, 2–4.5× faster than today. On ciphersuite 1 (X25519,
Ed25519) the gain is smaller, 10–30%, and graviola loses it for large messages. RustCrypto stays in any case, because
neither library builds for the browser.

**I'd choose aws-lc-rs with RustCrypto.** Since `main` builds with `opt-level = 3`, the two libraries are close:

- On ciphersuite 2 they tie for creating groups and for messages. graviola is ahead for commits (0.24× of today's time
  against 0.28×) and key packages (0.29× against 0.41×), because its P-256 signing is faster.
- On ciphersuite 1 they tie, except that graviola is faster for commits (0.69× against 0.74×) and slower for large
  messages (1.08× against 0.90×). Ed25519 hashes the whole message with SHA-512, and graviola's SHA-512 is 2.5× slower
  than RustCrypto's. Signing a 64 KiB message takes it 2.2× as long as today.
- On ciphersuite 7 (P-384), aws-lc is ahead nearly everywhere.
- aws-lc-rs runs on 32-bit ARM Android, which we ship, and on x86_64 and aarch64 CPUs without the extensions graviola
  needs (the Android emulator, older devices). With graviola those stay on RustCrypto.
- It covers P-521, and is faster at ChaCha20-Poly1305 and SHA-384/512, where graviola is slower than RustCrypto.
- It is a released crate, maintained by AWS, with an optional FIPS mode. graviola is pinned to a git revision until a
  release with the iOS fix appears, has one maintainer, and needs us to keep a copy of its CPU feature list in sync.
- Against that, it adds about 0.5 MB more to each mobile library than graviola does, and the first ECDSA signature in
  each process costs about 30 ms, while aws-lc seeds its random number generator. See [smaller points](#smaller-points).

Before deciding, I'd measure on a real mid-range Android phone. At these margins the Mac's numbers can't settle it.

A three-way chain (graviola, then aws-lc-rs, then RustCrypto) isn't worth it at these margins. It would add about 3 MB
to each mobile library, and a second native library to keep at parity with RustCrypto.

**Whatever we choose**, PR #2670 has a bug that needs fixing first; see
[Ed25519 small-order keys](#ed25519-small-order-keys).

## What was compared

All variants share the same code base (`main` at `c7087be13e`), so the only difference is the crypto backend. That
commit predates `b52faa7f59`, which moved our release profile to `opt-level = 3` for native targets. The benchmark sets
the same profile itself, so every variant is built as `main` now ships it.

| variant    | branch                                                                     | crypto                                                                                                                                     |
| ---------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `main`     | `main`                                                                     | RustCrypto for everything; signing through the openmls fork's `DefaultSigner`                                                              |
| `graviola` | `simon/spike/graviola-on-main` (local: #2670 rebased onto `main`, widened) | graviola for hashes, AES-GCM, ChaCha20-Poly1305, HKDF, Ed25519/P-256/P-384 signatures and HPKE; RustCrypto for P-521 and ML-DSA; CPU check |
| `aws-lc`   | `simon/chore/graviola-vs-aws-lc-rs-WPB-29267`                              | aws-lc-rs for all of the above, P-521 included; RustCrypto for ML-DSA and in the browser                                                   |

The `aws-lc` variant is built with `AWS_LC_SYS_NO_JITTER_ENTROPY=1`, for the benchmark only. Without it, aws-lc spends
about 30 ms seeding its random number generator the first time it needs randomness. Each benchmark run is a new process,
so that one-off cost would land in every run and dominate the short ones. A shipped build would keep the jitter source.

Both variants go further than #2670 did, so that the comparison covers everything the provider does:

- Signing goes through our provider. On `main` openmls signs with its own `DefaultSigner`, so we now pass openmls a
  `ProviderSigner` instead. Building against a copy of the openmls fork without the `DefaultSigner` blanket impl showed
  that no call site was missed, and that openmls never signs with anything else.
- HKDF and HPKE use the library too. Neither library offers an HPKE we could use, so `backend/hpke.rs` implements RFC
  9180 once over a small trait, which each library implements. It passes the RFC 9180 test vectors and interoperates
  with the `hpke` crate in both directions. The post-quantum KEMs stay on the `hpke` crate.

Each backend has tests showing it agrees with RustCrypto: same output where the output is deterministic, each accepts
what the other produces, and the same errors for malformed input. That matters because a conversation can include a
browser client, which always uses RustCrypto.

## Results

Measured on an Apple Silicon Mac (aarch64), on AC power, with `hyperfine`. Numbers are wall time relative to `main`;
lower is faster. Each run is a separate process that does some setup and then the measured work, so very short runs
include process start-up. Differences under about 10% are within noise.

### MLS operations

Through the public API, one transaction per operation, as clients do it. "100 members" means a conversation of 100
clients, each with its own database. Ciphersuites 1 and 2 are Wire's defaults.

| ciphersuite                  | scenario                      | graviola |   aws-lc |
| ---------------------------- | ----------------------------- | -------: | -------: |
| 1 (X25519, Ed25519, AES-128) | commits, 100 members          |     0.69 |     0.74 |
|                              | create group, 100 members     |     0.78 |     0.76 |
|                              | messages, 64 B, 100 members   |     0.94 |     0.89 |
|                              | messages, 64 KiB, 100 members |     1.08 | **0.90** |
|                              | key packages                  |     0.76 |     0.76 |
| 2 (P-256)                    | commits, 100 members          | **0.24** |     0.28 |
|                              | create group, 100 members     |     0.22 |     0.21 |
|                              | messages, 64 B, 100 members   |     0.45 |     0.45 |
|                              | messages, 64 KiB, 100 members |     0.47 |     0.48 |
|                              | key packages                  | **0.29** |     0.41 |
| 7 (P-384)                    | commits, 100 members          |     0.34 |     0.36 |
|                              | create group, 100 members     |     0.37 | **0.26** |
|                              | messages, 64 B, 100 members   |     0.49 | **0.41** |
|                              | key packages                  |     0.59 | **0.48** |

Bold marks a lead of more than 10%.

### Primitives

The provider called directly, 100 to 100,000 times per run, on 1 KiB of data unless noted.

| primitive                         | graviola               | aws-lc                     |
| --------------------------------- | ---------------------- | -------------------------- |
| AES-GCM, 1 KiB / 64 KiB           | 1.05 / 0.71            | **0.86** / 0.65            |
| ChaCha20-Poly1305, 1 KiB / 64 KiB | 1.41 / 1.45 (slower)   | **0.62 / 0.50**            |
| SHA-256                           | 1.04                   | **0.92**                   |
| SHA-384, SHA-512                  | 2.5 (slower)           | **1.0**                    |
| HKDF-SHA256 extract / expand      | **0.85 / 1.23**        | 1.35 / 1.94 (slower)       |
| HKDF-SHA384/512 extract / expand  | 1.7 / 2.4 (slower)     | **1.0 / 1.35**             |
| Ed25519 keygen / sign / verify    | 0.62 / 0.63 / 0.83     | 0.61 / 0.62 / 0.78         |
| Ed25519 sign / verify, 64 KiB ¹   | 2.2 / 1.8 (slower)     | **0.92 / 0.91**            |
| X25519 HPKE seal / open           | **0.56 / 0.67**        | 0.67 / 0.80                |
| P-256 keygen / sign ² / verify    | **0.27 / 0.17** / 0.21 | 0.37 / 0.38 / 0.20         |
| P-256 HPKE seal / open            | 0.25 / **0.22**        | 0.26 / 0.31                |
| P-384 keygen / sign ² / verify    | 0.76 / **0.44** / 0.36 | **0.58** / 0.51 / **0.26** |
| P-384 HPKE seal / open            | **0.30 / 0.34**        | 0.33 / 0.39                |
| P-521 keygen / sign ² / verify    | 1.0 (RustCrypto)       | **0.87** / 0.97 / **0.57** |
| P-521 HPKE seal / open            | 1.0 (RustCrypto)       | **0.62 / 0.77**            |

¹ Measured separately with `hyperfine`, in the same way, but not part of `run.sh`.

² Without the public key. The primitive benchmark calls `OpenMlsCrypto::sign`, which only gets the private key. MLS
signs through `ProviderSigner`, which also passes aws-lc the public key; see [smaller points](#smaller-points).

[Full results](#full-results) has every scenario, with absolute times and standard deviations.

### Library size

Stripped release builds of `core-crypto-ffi`, built the way the Makefile builds them, with `opt-level = 3`. The shared
library is the better guide to what an app ships; a static library includes code the app's linker drops.

| variant    | iOS `.dylib`      | Android `.so`     | iOS / Android `.a` |
| ---------- | ----------------- | ----------------- | ------------------ |
| `main`     | 16.11 MB          | 17.54 MB          | 35.9 / 53.4 MB     |
| `graviola` | +1.21 MB (+7.5%)  | +1.21 MB (+6.9%)  | +1.3 / +1.3 MB     |
| `aws-lc`   | +1.66 MB (+10.3%) | +1.84 MB (+10.5%) | +4.4 / +6.4 MB     |

For comparison, `main` built with the old `opt-level = "s"` was 11.73 MB on iOS and 12.86 MB on Android: the profile
change alone added about 4.5 MB, much more than either library.

### Where each library builds

| target                  | graviola                                        | aws-lc-rs | RustCrypto |
| ----------------------- | ----------------------------------------------- | --------- | ---------- |
| aarch64 iOS and Android | yes                                             | yes       | yes        |
| x86_64 Android          | builds; falls back at runtime without BMI1 etc. | yes       | yes        |
| armv7 Android           | no ("only supports x86_64 or aarch64")          | yes       | yes        |
| wasm32 (browser)        | no                                              | no        | yes        |

aws-lc-rs was checked by building and linking the full `core-crypto-ffi` library for armv7 and x86_64 Android, with the
NDK. graviola and aws-lc-rs were each built on their own for wasm32 and armv7.

## Things we learned

### Ed25519 small-order keys

graviola and aws-lc both accept the signature `R = identity, S = 0` on any message under the identity public key.
RustCrypto rejects it, because we verify with ed25519-dalek's `verify_strict`. A forgery under a small-order key only
matters to someone who chose that key, but the disagreement matters a lot: a member could publish such a key and send a
commit that native clients accept and browser clients reject, and the conversation would split.

Both spike branches reject small-order public keys and `R` values before calling the library, using libsodium's list of
small-order encodings. **PR #2670 needs the same fix.**

### The opt-level matters a lot

The first round of measurements used the release profile from before `b52faa7f59`, `opt-level = "s"`. Moving to
`opt-level = 3` changed the picture:

- RustCrypto got 10–25% faster across the MLS operations, and its AES-GCM about 3× faster. Much of what looked like
  graviola's and aws-lc's advantage was the size-optimised build of RustCrypto.
- aws-lc got 2–10× faster on the NIST curves. aws-lc-sys checks the opt-level it is built with, and for `"s"` or `"z"`
  builds aws-lc with `OPENSSL_SMALL`, which drops the precomputed tables for those curves. At `opt-level = 3` that no
  longer happens. The browser build still uses `"s"`, but aws-lc isn't part of it. If a native build ever goes back to
  `"s"`, it should set `AWS_LC_SYS_SMALL=0`.
- graviola didn't change. Its hot paths are hand-written assembly.

### Smaller points

- aws-lc's ECDSA signing can't match graviola's through aws-lc-rs. To load a private key, aws-lc needs the public key as
  well. Given only the scalar, it computes the public key, and then computes it once more to check the pair, so a
  signature costs three scalar multiplications instead of one. `ProviderSigner` now passes it the public key, which
  saves one of them: a P-256 signature takes 28 µs instead of 35 µs, against graviola's 15 µs. In the MLS scenarios that
  gained 1–10%. Parsing each key only once would get to about 19 µs, but needs a cache of parsed keys.
- aws-lc seeds its random number generator from CPU jitter as well as the OS, which takes about 30 ms on this Mac. It
  happens once per process, on the first ECDSA signature: that is the only place aws-lc draws its own randomness, so
  ciphersuite 1 never pays it. The benchmark turns the jitter source off; see [what was compared](#what-was-compared).
- HKDF on aws-lc is slower than RustCrypto: it is many short HMAC calls into C. `hkdf::Prk` can't be used instead,
  because it panics on a PRK longer than 64 bytes, which RustCrypto accepts. HKDF is a small part of any MLS operation,
  but it could stay on RustCrypto.
- Neither library's ECDSA uses our reseedable RNG for nonces: both draw randomness themselves. Signatures stay valid;
  they just aren't deterministic as RustCrypto's are.
- RustCrypto's P-256/384 `SigningKey::from_slice` accepts a key a byte or two short and pads it with zeros; graviola and
  aws-lc reject it. Our own keys are always full length, so only a corrupted key would notice.

## Limits

- Only an Apple Silicon Mac was measured. Numbers from iOS simulators or Android emulators would be meaningless, so
  there are none, and x86_64 isn't covered either. Real devices are the obvious next measurement, especially a mid-range
  Android phone.
- On `main`, signing goes through openmls's own signer; in both variants it goes through our provider. That is part of
  what the variants change, so it is included in their numbers.
- graviola has no P-521; its P-521 numbers are RustCrypto's.
- #2670's original, narrower scope (no signing, HKDF or HPKE) wasn't measured separately.

## Reproducing

From the repository root, with `hyperfine` installed:

```sh
cc-bench/build-variants.sh main=c7087be13e graviola=simon/spike/graviola-on-main \
  aws-lc=simon/chore/graviola-vs-aws-lc-rs-WPB-29267,AWS_LC_SYS_NO_JITTER_ENTROPY=1
cc-bench/run.sh
cc-bench/summarize.py
```

The full matrix takes about 25 minutes. Pass a glob to `run.sh` to run part of it, for example
`cc-bench/run.sh 'mls-cs2-*'`, and set `RESULTS` to write somewhere other than `cc-bench/results`.

## Full results

Every scenario `run.sh` runs, as hyperfine reported it: mean ± standard deviation of the whole process's wall time, and
in brackets the ratio to `main`. MLS scenarios ran 10 times per variant, primitives 20 times, each after a warm-up. The
tables above are taken from these.

Measured on an Apple M3 Pro with 36 GB of memory, macOS 26.7, hyperfine 2.0.0, on 4 and 5 November 2026. The variants
were built from these commits:

| variant    | built from                                                                                |
| ---------- | ----------------------------------------------------------------------------------------- |
| `main`     | `c7087be13e`                                                                              |
| `graviola` | the commits of `simon/spike/graviola-on-main` up to `8faa1573f3`, applied to `c7087be13e` |
| `aws-lc`   | the commits of this branch up to `21b63a72ff`, applied to `c7087be13e`                    |

Both branches have since been rebased onto `073870efdf`. That brought in the `opt-level = 3` profile, which the
benchmark sets anyway, a patch release of `hpke` (0.15.1) and a cargo-deny exception. None of them should move these
numbers.

Scenario names give the ciphersuite (`cs1`) and, for MLS, the number of members (`m100`) and the message size. A
`-setup` scenario does only the setup of the scenario it's named after (`--setup-only`), so subtracting it from the full
run leaves the measured work.

### MLS operations, in full

| scenario                          | arguments                                                             |               main |                 graviola |                   aws-lc |
| --------------------------------- | --------------------------------------------------------------------- | -----------------: | -----------------------: | -----------------------: |
| `mls-cs1-commits-m10`             | `--ciphersuite 1 mls commits --members 10 --count 100`                |     190.3 ± 1.2 ms |   144.9 ± 2.5 ms (0.76×) |   155.3 ± 1.3 ms (0.82×) |
| `mls-cs1-commits-m100`            | `--ciphersuite 1 mls commits --members 100 --count 100`               |   1089.6 ± 26.7 ms |  753.1 ± 33.7 ms (0.69×) |  809.1 ± 10.2 ms (0.74×) |
| `mls-cs1-create-group-m10`        | `--ciphersuite 1 mls create-group --members 10`                       |      32.4 ± 1.6 ms |    31.0 ± 0.8 ms (0.96×) |    31.0 ± 0.7 ms (0.96×) |
| `mls-cs1-create-group-m100`       | `--ciphersuite 1 mls create-group --members 100`                      |  1156.5 ± 133.2 ms |  903.9 ± 17.6 ms (0.78×) |   879.2 ± 6.4 ms (0.76×) |
| `mls-cs1-create-group-setup-m10`  | `--ciphersuite 1 --setup-only mls create-group --members 10`          |      18.4 ± 0.8 ms |    18.5 ± 0.5 ms (1.01×) |    18.7 ± 0.4 ms (1.02×) |
| `mls-cs1-create-group-setup-m100` | `--ciphersuite 1 --setup-only mls create-group --members 100`         |      97.6 ± 1.6 ms |    91.5 ± 1.4 ms (0.94×) |    95.4 ± 5.1 ms (0.98×) |
| `mls-cs1-keypackages`             | `--ciphersuite 1 mls keypackages --count 200`                         |      30.0 ± 0.4 ms |    22.7 ± 0.5 ms (0.76×) |    22.8 ± 0.7 ms (0.76×) |
| `mls-cs1-messages-m10-64b`        | `--ciphersuite 1 mls messages --members 10 --count 1000 --size 64`    |     135.5 ± 0.8 ms |   113.4 ± 0.8 ms (0.84×) |   113.9 ± 0.7 ms (0.84×) |
| `mls-cs1-messages-m10-64k`        | `--ciphersuite 1 mls messages --members 10 --count 100 --size 65536`  |      58.5 ± 1.7 ms |    80.7 ± 0.6 ms (1.38×) |    54.5 ± 3.9 ms (0.93×) |
| `mls-cs1-messages-m100-64b`       | `--ciphersuite 1 mls messages --members 100 --count 1000 --size 64`   |     305.4 ± 2.3 ms |   286.4 ± 2.7 ms (0.94×) |   271.7 ± 0.8 ms (0.89×) |
| `mls-cs1-messages-m100-64k`       | `--ciphersuite 1 mls messages --members 100 --count 100 --size 65536` |     159.7 ± 3.4 ms |   172.4 ± 1.0 ms (1.08×) |   143.9 ± 0.7 ms (0.90×) |
| `mls-cs1-setup-m10`               | `--ciphersuite 1 --setup-only mls commits --members 10`               |      21.2 ± 0.8 ms |    21.0 ± 0.6 ms (0.99×) |    22.4 ± 2.8 ms (1.06×) |
| `mls-cs1-setup-m100`              | `--ciphersuite 1 --setup-only mls commits --members 100`              |     117.0 ± 1.5 ms |  113.8 ± 20.9 ms (0.97×) |   109.0 ± 3.4 ms (0.93×) |
| `mls-cs2-commits-m10`             | `--ciphersuite 2 mls commits --members 10 --count 100`                |     598.3 ± 0.7 ms |   179.1 ± 2.0 ms (0.30×) |   210.5 ± 0.9 ms (0.35×) |
| `mls-cs2-commits-m100`            | `--ciphersuite 2 mls commits --members 100 --count 100`               |   4177.2 ± 49.0 ms | 1007.8 ± 62.9 ms (0.24×) |  1183.4 ± 7.6 ms (0.28×) |
| `mls-cs2-create-group-m10`        | `--ciphersuite 2 mls create-group --members 10`                       |      89.2 ± 1.7 ms |    34.6 ± 0.7 ms (0.39×) |    34.9 ± 1.3 ms (0.39×) |
| `mls-cs2-create-group-m100`       | `--ciphersuite 2 mls create-group --members 100`                      |   5528.1 ± 45.4 ms |  1208.8 ± 4.6 ms (0.22×) | 1169.0 ± 25.7 ms (0.21×) |
| `mls-cs2-create-group-setup-m10`  | `--ciphersuite 2 --setup-only mls create-group --members 10`          |      21.1 ± 0.5 ms |    17.6 ± 0.6 ms (0.83×) |    18.5 ± 1.0 ms (0.88×) |
| `mls-cs2-create-group-setup-m100` | `--ciphersuite 2 --setup-only mls create-group --members 100`         |     131.7 ± 5.8 ms |    93.9 ± 1.7 ms (0.71×) |    98.4 ± 1.2 ms (0.75×) |
| `mls-cs2-keypackages`             | `--ciphersuite 2 mls keypackages --count 200`                         |      80.6 ± 0.6 ms |    23.3 ± 0.6 ms (0.29×) |    32.7 ± 2.0 ms (0.41×) |
| `mls-cs2-messages-m10-64b`        | `--ciphersuite 2 mls messages --members 10 --count 1000 --size 64`    |     453.5 ± 3.2 ms |   140.4 ± 4.5 ms (0.31×) |   151.7 ± 3.1 ms (0.33×) |
| `mls-cs2-messages-m10-64k`        | `--ciphersuite 2 mls messages --members 10 --count 100 --size 65536`  |      93.6 ± 1.6 ms |    46.0 ± 0.5 ms (0.49×) |    48.9 ± 5.7 ms (0.52×) |
| `mls-cs2-messages-m100-64b`       | `--ciphersuite 2 mls messages --members 100 --count 1000 --size 64`   |    793.3 ± 12.6 ms |  353.2 ± 33.3 ms (0.45×) |   358.9 ± 3.2 ms (0.45×) |
| `mls-cs2-messages-m100-64k`       | `--ciphersuite 2 mls messages --members 100 --count 100 --size 65536` |     326.2 ± 2.8 ms |   152.6 ± 1.5 ms (0.47×) |   157.8 ± 1.7 ms (0.48×) |
| `mls-cs2-setup-m10`               | `--ciphersuite 2 --setup-only mls commits --members 10`               |      36.0 ± 0.6 ms |    20.5 ± 1.0 ms (0.57×) |    22.8 ± 1.2 ms (0.63×) |
| `mls-cs2-setup-m100`              | `--ciphersuite 2 --setup-only mls commits --members 100`              |     259.4 ± 3.9 ms |   116.3 ± 0.9 ms (0.45×) |  129.1 ± 10.4 ms (0.50×) |
| `mls-cs7-commits-m10`             | `--ciphersuite 7 mls commits --members 10 --count 100`                |   1589.2 ± 16.8 ms |  682.6 ± 26.4 ms (0.43×) |  641.7 ± 17.6 ms (0.40×) |
| `mls-cs7-commits-m100`            | `--ciphersuite 7 mls commits --members 100 --count 100`               |  11402.5 ± 65.5 ms | 3917.8 ± 45.9 ms (0.34×) | 4070.0 ± 94.5 ms (0.36×) |
| `mls-cs7-create-group-m10`        | `--ciphersuite 7 mls create-group --members 10`                       |     218.0 ± 1.0 ms |    94.7 ± 1.3 ms (0.43×) |    75.9 ± 2.7 ms (0.35×) |
| `mls-cs7-create-group-m100`       | `--ciphersuite 7 mls create-group --members 100`                      | 15695.0 ± 113.6 ms | 5788.3 ± 38.5 ms (0.37×) | 4103.1 ± 46.4 ms (0.26×) |
| `mls-cs7-create-group-setup-m10`  | `--ciphersuite 7 --setup-only mls create-group --members 10`          |      28.7 ± 0.3 ms |    23.6 ± 0.6 ms (0.82×) |    21.7 ± 0.9 ms (0.76×) |
| `mls-cs7-create-group-setup-m100` | `--ciphersuite 7 --setup-only mls create-group --members 100`         |     201.2 ± 2.8 ms |  164.4 ± 26.3 ms (0.82×) |   140.1 ± 1.0 ms (0.70×) |
| `mls-cs7-keypackages`             | `--ciphersuite 7 mls keypackages --count 200`                         |     212.3 ± 3.0 ms |  125.9 ± 13.7 ms (0.59×) |   102.7 ± 4.5 ms (0.48×) |
| `mls-cs7-messages-m10-64b`        | `--ciphersuite 7 mls messages --members 10 --count 1000 --size 64`    |   1203.4 ± 21.3 ms |  526.2 ± 30.1 ms (0.44×) |   397.7 ± 1.1 ms (0.33×) |
| `mls-cs7-messages-m10-64k`        | `--ciphersuite 7 mls messages --members 10 --count 100 --size 65536`  |    208.3 ± 20.9 ms |   122.0 ± 0.9 ms (0.59×) |    87.3 ± 0.6 ms (0.42×) |
| `mls-cs7-messages-m100-64b`       | `--ciphersuite 7 mls messages --members 100 --count 1000 --size 64`   |   1847.8 ± 11.2 ms |   898.0 ± 9.7 ms (0.49×) |  753.8 ± 31.8 ms (0.41×) |
| `mls-cs7-messages-m100-64k`       | `--ciphersuite 7 mls messages --members 100 --count 100 --size 65536` |    766.9 ± 19.0 ms |   410.4 ± 5.1 ms (0.54×) |   311.0 ± 2.3 ms (0.41×) |
| `mls-cs7-setup-m10`               | `--ciphersuite 7 --setup-only mls commits --members 10`               |      72.8 ± 1.7 ms |    40.7 ± 2.4 ms (0.56×) |    34.2 ± 2.0 ms (0.47×) |
| `mls-cs7-setup-m100`              | `--ciphersuite 7 --setup-only mls commits --members 100`              |    629.5 ± 95.3 ms |   296.4 ± 0.9 ms (0.47×) |   246.9 ± 2.3 ms (0.39×) |

### Primitives, in full

| scenario                            | arguments                                                             |            main |                graviola |                  aws-lc |
| ----------------------------------- | --------------------------------------------------------------------- | --------------: | ----------------------: | ----------------------: |
| `primitive-cs1-aead-open-1k`        | `--ciphersuite 1 primitive aead-open --iterations 50000 --size 1024`  |   33.8 ± 0.6 ms |   31.6 ± 2.4 ms (0.93×) |   25.0 ± 0.6 ms (0.74×) |
| `primitive-cs1-aead-seal-1k`        | `--ciphersuite 1 primitive aead-seal --iterations 50000 --size 1024`  |   33.1 ± 0.5 ms |   34.7 ± 0.5 ms (1.05×) |   28.3 ± 0.5 ms (0.86×) |
| `primitive-cs1-aead-seal-64k`       | `--ciphersuite 1 primitive aead-seal --iterations 1000 --size 65536`  |   24.6 ± 0.4 ms |   17.5 ± 1.6 ms (0.71×) |   16.0 ± 1.1 ms (0.65×) |
| `primitive-cs1-hash-1k`             | `--ciphersuite 1 primitive hash --iterations 100000 --size 1024`      |   67.7 ± 0.6 ms |   70.2 ± 1.6 ms (1.04×) |   62.6 ± 0.6 ms (0.92×) |
| `primitive-cs1-hkdf-expand`         | `--ciphersuite 1 primitive hkdf-expand --iterations 100000`           |   23.5 ± 0.3 ms |   28.8 ± 1.5 ms (1.23×) |   45.6 ± 0.8 ms (1.94×) |
| `primitive-cs1-hkdf-extract`        | `--ciphersuite 1 primitive hkdf-extract --iterations 50000 --size 64` |   19.0 ± 0.4 ms |   16.2 ± 0.4 ms (0.85×) |   25.7 ± 0.3 ms (1.35×) |
| `primitive-cs1-hpke-derive-keypair` | `--ciphersuite 1 primitive hpke-derive-keypair --iterations 1000`     |   18.7 ± 0.4 ms |   12.6 ± 0.6 ms (0.67×) |   12.8 ± 0.2 ms (0.69×) |
| `primitive-cs1-hpke-open`           | `--ciphersuite 1 primitive hpke-open --iterations 500 --size 64`      |   31.9 ± 0.6 ms |   21.5 ± 1.8 ms (0.67×) |   25.6 ± 0.5 ms (0.80×) |
| `primitive-cs1-hpke-seal`           | `--ciphersuite 1 primitive hpke-seal --iterations 500 --size 64`      |   38.7 ± 2.0 ms |   21.7 ± 0.5 ms (0.56×) |   26.0 ± 0.3 ms (0.67×) |
| `primitive-cs1-sig-keygen`          | `--ciphersuite 1 primitive sig-keygen --iterations 1000`              |   19.4 ± 2.8 ms |   12.0 ± 0.3 ms (0.62×) |   11.9 ± 0.3 ms (0.61×) |
| `primitive-cs1-sig-sign`            | `--ciphersuite 1 primitive sig-sign --iterations 1000 --size 256`     |   34.2 ± 0.9 ms |   21.7 ± 1.1 ms (0.63×) |   21.0 ± 3.9 ms (0.62×) |
| `primitive-cs1-sig-verify`          | `--ciphersuite 1 primitive sig-verify --iterations 1000 --size 256`   |   49.1 ± 1.1 ms |   40.8 ± 1.2 ms (0.83×) |   38.3 ± 0.5 ms (0.78×) |
| `primitive-cs2-aead-open-1k`        | `--ciphersuite 2 primitive aead-open --iterations 50000 --size 1024`  |   33.9 ± 0.8 ms |   31.5 ± 0.5 ms (0.93×) |   25.7 ± 1.3 ms (0.76×) |
| `primitive-cs2-aead-seal-1k`        | `--ciphersuite 2 primitive aead-seal --iterations 50000 --size 1024`  |   33.5 ± 0.9 ms |   34.9 ± 0.6 ms (1.04×) |   28.7 ± 0.8 ms (0.86×) |
| `primitive-cs2-aead-seal-64k`       | `--ciphersuite 2 primitive aead-seal --iterations 1000 --size 65536`  |   24.8 ± 0.6 ms |   17.0 ± 1.0 ms (0.69×) |   17.1 ± 1.5 ms (0.69×) |
| `primitive-cs2-hash-1k`             | `--ciphersuite 2 primitive hash --iterations 100000 --size 1024`      |   68.1 ± 0.8 ms |   69.7 ± 0.5 ms (1.02×) |   64.5 ± 6.3 ms (0.95×) |
| `primitive-cs2-hkdf-expand`         | `--ciphersuite 2 primitive hkdf-expand --iterations 100000`           |   23.6 ± 0.4 ms |   28.4 ± 0.4 ms (1.20×) |   45.7 ± 1.8 ms (1.94×) |
| `primitive-cs2-hkdf-extract`        | `--ciphersuite 2 primitive hkdf-extract --iterations 50000 --size 64` |   19.4 ± 1.0 ms |   16.5 ± 1.6 ms (0.85×) |   25.9 ± 0.5 ms (1.33×) |
| `primitive-cs2-hpke-derive-keypair` | `--ciphersuite 2 primitive hpke-derive-keypair --iterations 1000`     |   60.9 ± 0.6 ms |   20.6 ± 7.0 ms (0.34×) |   25.3 ± 5.0 ms (0.42×) |
| `primitive-cs2-hpke-open`           | `--ciphersuite 2 primitive hpke-open --iterations 500 --size 64`      |  155.0 ± 5.6 ms |   34.2 ± 2.5 ms (0.22×) |  48.4 ± 13.1 ms (0.31×) |
| `primitive-cs2-hpke-seal`           | `--ciphersuite 2 primitive hpke-seal --iterations 500 --size 64`      |  180.4 ± 3.7 ms |  44.5 ± 20.6 ms (0.25×) |   47.4 ± 5.5 ms (0.26×) |
| `primitive-cs2-sig-keygen`          | `--ciphersuite 2 primitive sig-keygen --iterations 1000`              |   60.0 ± 0.6 ms |   16.2 ± 0.8 ms (0.27×) |   22.0 ± 0.5 ms (0.37×) |
| `primitive-cs2-sig-sign`            | `--ciphersuite 2 primitive sig-sign --iterations 1000 --size 256`     |  121.3 ± 1.3 ms |   20.3 ± 2.1 ms (0.17×) |   45.7 ± 4.5 ms (0.38×) |
| `primitive-cs2-sig-verify`          | `--ciphersuite 2 primitive sig-verify --iterations 1000 --size 256`   |  263.1 ± 2.6 ms |   54.0 ± 1.0 ms (0.21×) |   52.9 ± 1.3 ms (0.20×) |
| `primitive-cs3-aead-open-1k`        | `--ciphersuite 3 primitive aead-open --iterations 50000 --size 1024`  | 123.6 ± 28.5 ms |  147.0 ± 5.3 ms (1.19×) |   71.0 ± 0.6 ms (0.57×) |
| `primitive-cs3-aead-seal-1k`        | `--ciphersuite 3 primitive aead-seal --iterations 50000 --size 1024`  |  110.0 ± 1.9 ms | 155.6 ± 21.1 ms (1.41×) |   67.7 ± 7.2 ms (0.62×) |
| `primitive-cs3-aead-seal-64k`       | `--ciphersuite 3 primitive aead-seal --iterations 1000 --size 65536`  |  116.2 ± 2.3 ms |  168.3 ± 1.7 ms (1.45×) |   57.6 ± 0.5 ms (0.50×) |
| `primitive-cs3-hash-1k`             | `--ciphersuite 3 primitive hash --iterations 100000 --size 1024`      |   68.9 ± 2.4 ms |   71.6 ± 5.7 ms (1.04×) |  66.7 ± 10.8 ms (0.97×) |
| `primitive-cs3-hkdf-expand`         | `--ciphersuite 3 primitive hkdf-expand --iterations 100000`           |   23.4 ± 0.7 ms |   29.4 ± 2.3 ms (1.25×) |   45.7 ± 0.8 ms (1.95×) |
| `primitive-cs3-hkdf-extract`        | `--ciphersuite 3 primitive hkdf-extract --iterations 50000 --size 64` |   20.9 ± 3.0 ms |   17.4 ± 1.8 ms (0.83×) |   26.8 ± 1.8 ms (1.28×) |
| `primitive-cs3-hpke-derive-keypair` | `--ciphersuite 3 primitive hpke-derive-keypair --iterations 1000`     |   19.2 ± 0.6 ms |   12.9 ± 0.9 ms (0.67×) |   13.7 ± 1.3 ms (0.71×) |
| `primitive-cs3-hpke-open`           | `--ciphersuite 3 primitive hpke-open --iterations 500 --size 64`      |   32.7 ± 1.0 ms |   22.1 ± 1.8 ms (0.68×) |   26.5 ± 0.6 ms (0.81×) |
| `primitive-cs3-hpke-seal`           | `--ciphersuite 3 primitive hpke-seal --iterations 500 --size 64`      |   38.9 ± 0.6 ms |   22.6 ± 1.8 ms (0.58×) |   26.8 ± 0.7 ms (0.69×) |
| `primitive-cs3-sig-keygen`          | `--ciphersuite 3 primitive sig-keygen --iterations 1000`              |   20.0 ± 3.7 ms |   12.4 ± 0.7 ms (0.62×) |   12.4 ± 0.6 ms (0.62×) |
| `primitive-cs3-sig-sign`            | `--ciphersuite 3 primitive sig-sign --iterations 1000 --size 256`     |   33.3 ± 0.4 ms |   21.3 ± 0.5 ms (0.64×) |   20.3 ± 0.4 ms (0.61×) |
| `primitive-cs3-sig-verify`          | `--ciphersuite 3 primitive sig-verify --iterations 1000 --size 256`   |   49.7 ± 2.2 ms |   39.2 ± 0.6 ms (0.79×) |   39.2 ± 0.6 ms (0.79×) |
| `primitive-cs5-aead-open-1k`        | `--ciphersuite 5 primitive aead-open --iterations 50000 --size 1024`  |   36.8 ± 2.1 ms |   36.6 ± 0.6 ms (0.99×) |   29.4 ± 2.0 ms (0.80×) |
| `primitive-cs5-aead-seal-1k`        | `--ciphersuite 5 primitive aead-seal --iterations 50000 --size 1024`  |   35.9 ± 1.5 ms |   40.9 ± 1.8 ms (1.14×) |   31.3 ± 1.6 ms (0.87×) |
| `primitive-cs5-aead-seal-64k`       | `--ciphersuite 5 primitive aead-seal --iterations 1000 --size 65536`  |   25.8 ± 0.5 ms |   21.2 ± 3.3 ms (0.82×) |   19.6 ± 4.5 ms (0.76×) |
| `primitive-cs5-hash-1k`             | `--ciphersuite 5 primitive hash --iterations 100000 --size 1024`      |  106.6 ± 0.5 ms |  268.8 ± 0.9 ms (2.52×) |  107.6 ± 0.6 ms (1.01×) |
| `primitive-cs5-hkdf-expand`         | `--ciphersuite 5 primitive hkdf-expand --iterations 100000`           |   56.3 ± 0.9 ms |  133.8 ± 0.7 ms (2.38×) |   77.2 ± 1.0 ms (1.37×) |
| `primitive-cs5-hkdf-extract`        | `--ciphersuite 5 primitive hkdf-extract --iterations 50000 --size 64` |   41.8 ± 2.8 ms |   67.9 ± 0.3 ms (1.62×) |   40.3 ± 0.6 ms (0.96×) |
| `primitive-cs5-hpke-derive-keypair` | `--ciphersuite 5 primitive hpke-derive-keypair --iterations 1000`     |  143.8 ± 3.3 ms |  143.4 ± 1.2 ms (1.00×) |  146.7 ± 2.4 ms (1.02×) |
| `primitive-cs5-hpke-open`           | `--ciphersuite 5 primitive hpke-open --iterations 500 --size 64`      |  326.4 ± 3.9 ms |  331.2 ± 7.7 ms (1.01×) |  250.5 ± 5.4 ms (0.77×) |
| `primitive-cs5-hpke-seal`           | `--ciphersuite 5 primitive hpke-seal --iterations 500 --size 64`      |  395.1 ± 8.4 ms |  393.4 ± 3.1 ms (1.00×) |  245.3 ± 1.4 ms (0.62×) |
| `primitive-cs5-sig-keygen`          | `--ciphersuite 5 primitive sig-keygen --iterations 1000`              |  173.7 ± 1.4 ms | 177.9 ± 14.4 ms (1.02×) | 150.4 ± 11.8 ms (0.87×) |
| `primitive-cs5-sig-sign`            | `--ciphersuite 5 primitive sig-sign --iterations 1000 --size 256`     |  303.0 ± 2.9 ms |  301.6 ± 0.6 ms (1.00×) |  293.5 ± 4.7 ms (0.97×) |
| `primitive-cs5-sig-verify`          | `--ciphersuite 5 primitive sig-verify --iterations 1000 --size 256`   |  549.2 ± 9.4 ms |  546.1 ± 7.3 ms (0.99×) |  312.9 ± 3.2 ms (0.57×) |
| `primitive-cs7-aead-open-1k`        | `--ciphersuite 7 primitive aead-open --iterations 50000 --size 1024`  |   37.2 ± 4.9 ms |   36.2 ± 0.7 ms (0.97×) |   28.1 ± 1.4 ms (0.76×) |
| `primitive-cs7-aead-seal-1k`        | `--ciphersuite 7 primitive aead-seal --iterations 50000 --size 1024`  |   34.9 ± 1.7 ms |   39.6 ± 1.6 ms (1.14×) |   30.3 ± 1.2 ms (0.87×) |
| `primitive-cs7-aead-seal-64k`       | `--ciphersuite 7 primitive aead-seal --iterations 1000 --size 65536`  |   27.0 ± 1.1 ms |   23.0 ± 4.7 ms (0.85×) |   19.7 ± 1.8 ms (0.73×) |
| `primitive-cs7-hash-1k`             | `--ciphersuite 7 primitive hash --iterations 100000 --size 1024`      |  106.4 ± 1.8 ms |  272.4 ± 6.3 ms (2.56×) |  108.2 ± 2.6 ms (1.02×) |
| `primitive-cs7-hkdf-expand`         | `--ciphersuite 7 primitive hkdf-expand --iterations 100000`           |   57.2 ± 2.5 ms |  133.7 ± 2.0 ms (2.34×) |   76.1 ± 1.4 ms (1.33×) |
| `primitive-cs7-hkdf-extract`        | `--ciphersuite 7 primitive hkdf-extract --iterations 50000 --size 64` |   39.2 ± 0.5 ms |   70.6 ± 2.5 ms (1.80×) |   43.0 ± 3.1 ms (1.10×) |
| `primitive-cs7-hpke-derive-keypair` | `--ciphersuite 7 primitive hpke-derive-keypair --iterations 1000`     |  168.0 ± 3.0 ms |  134.3 ± 1.1 ms (0.80×) |   98.9 ± 0.5 ms (0.59×) |
| `primitive-cs7-hpke-open`           | `--ciphersuite 7 primitive hpke-open --iterations 500 --size 64`      | 427.6 ± 13.5 ms |  146.8 ± 0.6 ms (0.34×) |  165.0 ± 0.8 ms (0.39×) |
| `primitive-cs7-hpke-seal`           | `--ciphersuite 7 primitive hpke-seal --iterations 500 --size 64`      | 506.9 ± 19.1 ms | 152.7 ± 17.1 ms (0.30×) |  169.1 ± 6.8 ms (0.33×) |
| `primitive-cs7-sig-keygen`          | `--ciphersuite 7 primitive sig-keygen --iterations 1000`              |  174.3 ± 5.8 ms |  132.1 ± 0.9 ms (0.76×) | 100.9 ± 10.8 ms (0.58×) |
| `primitive-cs7-sig-sign`            | `--ciphersuite 7 primitive sig-sign --iterations 1000 --size 256`     |  343.4 ± 4.7 ms |  149.4 ± 2.8 ms (0.44×) |  175.2 ± 2.8 ms (0.51×) |
| `primitive-cs7-sig-verify`          | `--ciphersuite 7 primitive sig-verify --iterations 1000 --size 256`   | 752.9 ± 14.1 ms |  271.7 ± 2.4 ms (0.36×) | 192.9 ± 11.5 ms (0.26×) |
