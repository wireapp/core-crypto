// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.
#![allow(non_snake_case, dead_code, unused_macros, unused_imports, clippy::await_holding_lock)]

pub use rstest::*;
pub use rstest_reuse::{self, *};

mod fixtures;

const ITER_ROUNDS: usize = 10000;
const RAND_ARR_LEN: usize = 128;

#[cfg(test)]
mod tests {
    use crate::{fixtures::*, ITER_ROUNDS, RAND_ARR_LEN};
    use getrandom::getrandom;
    use mls_crypto_provider::{EntropySeed, MlsCryptoProvider};
    use openmls::prelude::Ciphersuite;
    use openmls_traits::{random::OpenMlsRand, OpenMlsCryptoProvider};
    use rand::RngCore as _;
    use sha2::{Digest, Sha256};

    use wasm_bindgen_test::*;
    wasm_bindgen_test_configure!(run_in_browser);

    fn test_randomness(backend: &mut MlsCryptoProvider, entropy: Option<EntropySeed>) {
        backend.reseed(entropy).unwrap();

        let random = backend.rand();
        let mut hashes = Vec::with_capacity(ITER_ROUNDS);

        for _ in 0..ITER_ROUNDS / 2 {
            let arr: [u8; RAND_ARR_LEN] = random.random_array().unwrap();
            let mut hasher = Sha256::new();
            hasher.update(arr);
            let hash = hasher.finalize();
            if hashes.contains(&hash) {
                panic!("Entropy isn't sufficient")
            }
            hashes.push(hash);
        }

        for _ in 0..ITER_ROUNDS / 2 {
            let arr = random.random_vec(RAND_ARR_LEN).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(arr);
            let hash = hasher.finalize();
            if hashes.contains(&hash) {
                panic!("Entropy isn't sufficient")
            }
            hashes.push(hash);
        }
    }

    #[apply(use_provider)]
    #[wasm_bindgen_test]
    async fn can_generate_sufficient_randomness_ext_entropy(backend: MlsCryptoProvider) {
        let mut backend = backend.await;
        test_randomness(&mut backend, Some(entropy()));
        teardown(backend).await;
    }

    #[apply(use_provider)]
    #[wasm_bindgen_test]
    async fn can_generate_sufficient_randomness_sys_entropy(backend: MlsCryptoProvider) {
        let mut backend = backend.await;
        test_randomness(&mut backend, None);
        teardown(backend).await;
    }

    // ? Test vectors taken from https://github.com/rust-random/rand/blob/c797f070b125084d727dc0ba5104bbdae966ba78/rand_chacha/src/chacha.rs#L411

    #[apply(use_provider)]
    #[wasm_bindgen_test]
    async fn can_be_externally_seeded_ietf_vectors_1_2(backend: MlsCryptoProvider) {
        let backend = backend.await;
        // Test vectors 1 and 2 from
        // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04
        let seed = [0u8; 32];
        backend.reseed(Some(EntropySeed::from_raw(seed))).unwrap();
        let mut rng = backend.rand().borrow_rand().unwrap();

        let mut results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng.next_u32();
        }
        let expected = [
            0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653, 0xb819d2bd, 0x1aed8da0, 0xccef36a8, 0xc70d778b, 0x7c5941da,
            0x8d485751, 0x3fe02477, 0x374ad8b8, 0xf4b8436a, 0x1ca11815, 0x69b687c3, 0x8665eeb2,
        ];
        assert_eq!(results, expected);

        for i in results.iter_mut() {
            *i = rng.next_u32();
        }
        let expected = [
            0xbee7079f, 0x7a385155, 0x7c97ba98, 0x0d082d73, 0xa0290fcb, 0x6965e348, 0x3e53c612, 0xed7aee32, 0x7621b729,
            0x434ee69c, 0xb03371d5, 0xd539d874, 0x281fed31, 0x45fb0a51, 0x1f0ae1ac, 0x6f4d794b,
        ];
        assert_eq!(results, expected);

        drop(rng);

        teardown(backend).await;
    }

    #[apply(use_provider)]
    #[wasm_bindgen_test]
    async fn can_be_externally_seeded_ietf_vector_3(backend: MlsCryptoProvider) {
        let backend = backend.await;
        // Test vector 3 from
        // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04
        let seed = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        backend.reseed(Some(EntropySeed::from_raw(seed))).unwrap();
        let mut rng = backend.rand().borrow_rand().unwrap();

        // Skip block 0
        for _ in 0..16 {
            rng.next_u32();
        }

        let mut results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng.next_u32();
        }
        let expected = [
            0x2452eb3a, 0x9249f8ec, 0x8d829d9b, 0xddd4ceb1, 0xe8252083, 0x60818b01, 0xf38422b8, 0x5aaa49c9, 0xbb00ca8e,
            0xda3ba7b4, 0xc4b592d1, 0xfdf2732f, 0x4436274e, 0x2561b3c8, 0xebdd4aa6, 0xa0136c00,
        ];
        assert_eq!(results, expected);

        drop(rng);

        teardown(backend).await;
    }

    #[apply(use_provider)]
    #[wasm_bindgen_test]
    async fn can_be_externally_seeded_ietf_vector_4(backend: MlsCryptoProvider) {
        let backend = backend.await;
        // Test vector 4 from
        // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04
        let seed = [
            0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let expected = [
            0xfb4dd572, 0x4bc42ef1, 0xdf922636, 0x327f1394, 0xa78dea8f, 0x5e269039, 0xa1bebbc1, 0xcaf09aae, 0xa25ab213,
            0x48a6b46c, 0x1b9d9bcb, 0x092c5be6, 0x546ca624, 0x1bec45d5, 0x87f47473, 0x96f0992e,
        ];
        let expected_end = 3 * 16;
        let mut results = [0u32; 16];

        // Test block 2 by skipping block 0 and 1
        backend.reseed(Some(EntropySeed::from_raw(seed))).unwrap();
        let mut rng1 = backend.rand().borrow_rand().unwrap();
        for _ in 0..32 {
            rng1.next_u32();
        }
        for i in results.iter_mut() {
            *i = rng1.next_u32();
        }
        assert_eq!(results, expected);
        assert_eq!(rng1.get_word_pos(), expected_end);

        drop(rng1);

        // Test block 2 by using `set_word_pos`
        backend.reseed(Some(EntropySeed::from_raw(seed))).unwrap();
        let mut rng2 = backend.rand().borrow_rand().unwrap();
        rng2.set_word_pos(2 * 16);
        for i in results.iter_mut() {
            *i = rng2.next_u32();
        }
        assert_eq!(results, expected);
        assert_eq!(rng2.get_word_pos(), expected_end);

        let mut buf = [0u8; 32];
        rng2.fill_bytes(&mut buf[..]);
        assert_eq!(rng2.get_word_pos(), expected_end + 8);
        rng2.fill_bytes(&mut buf[0..25]);
        assert_eq!(rng2.get_word_pos(), expected_end + 15);
        rng2.next_u64();
        assert_eq!(rng2.get_word_pos(), expected_end + 17);
        rng2.next_u32();
        rng2.next_u64();
        assert_eq!(rng2.get_word_pos(), expected_end + 20);
        rng2.fill_bytes(&mut buf[0..1]);
        assert_eq!(rng2.get_word_pos(), expected_end + 21);

        drop(rng2);
        teardown(backend).await;
    }

    #[apply(use_provider)]
    #[wasm_bindgen_test]
    async fn can_be_externally_seeded_ietf_vector_5(backend: MlsCryptoProvider) {
        let backend = backend.await;
        // Test vector 5 from
        // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04
        let seed = [0u8; 32];
        backend.reseed(Some(EntropySeed::from_raw(seed))).unwrap();
        let mut rng = backend.rand().borrow_rand().unwrap();
        // 96-bit nonce in LE order is: 0,0,0,0, 0,0,0,0, 0,0,0,2
        rng.set_stream(2u64 << (24 + 32));

        let mut results = [0u32; 16];
        for i in results.iter_mut() {
            *i = rng.next_u32();
        }
        let expected = [
            0x374dc6c2, 0x3736d58c, 0xb904e24a, 0xcd3f93ef, 0x88228b1a, 0x96a4dfb3, 0x5b76ab72, 0xc727ee54, 0x0e0e978a,
            0xf3145c95, 0x1b748ea8, 0xf786c297, 0x99c28f5f, 0x628314e8, 0x398a19fa, 0x6ded1b53,
        ];
        assert_eq!(results, expected);

        drop(rng);
        teardown(backend).await;
    }
}
