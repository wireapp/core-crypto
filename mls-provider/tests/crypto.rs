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
#![allow(non_snake_case, dead_code, unused_macros, unused_imports)]

pub use rstest::*;
pub use rstest_reuse::{self, *};

const LEN_RANGE: std::ops::RangeInclusive<usize> = 128..=1024;

mod fixtures;

#[cfg(test)]
mod tests {
    use crate::fixtures::*;
    use crate::LEN_RANGE;
    use hex_literal::hex;
    use mls_crypto_provider::{EntropySeed, MlsCryptoProvider};
    use openmls::prelude::Ciphersuite;
    use openmls_traits::types::HpkeKeyPair;
    use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, OpenMlsCryptoProvider};
    use rand::Rng;

    use wasm_bindgen_test::*;
    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(use_provider)]
    #[wasm_bindgen_test]
    async fn ciphersuite_support_is_consistent(backend: MlsCryptoProvider) {
        let backend = backend.await;
        let crypto = backend.crypto();
        let supported = crypto.supported_ciphersuites();
        for supported_cs in supported.into_iter() {
            crypto.supports(supported_cs).unwrap();
        }

        teardown(backend).await;
    }

    #[apply(all_storage_types_and_ciphersuites)]
    #[wasm_bindgen_test]
    async fn hkdf_is_consistent(
        backend: MlsCryptoProvider,
        ciphersuite: Ciphersuite,
        entropy_seed: Option<EntropySeed>,
    ) {
        let backend = backend.await;
        backend.reseed(entropy_seed).unwrap();
        let len = rand::thread_rng().gen_range(LEN_RANGE);
        let crypto = backend.crypto();
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let prk = crypto
            .hkdf_extract(ciphersuite.hash_algorithm(), &salt, &ikm)
            .unwrap()
            .as_slice()
            .to_vec();
        let supposed_prk_len = ciphersuite.hash_length();
        assert_eq!(prk.len(), supposed_prk_len);

        let okm = crypto
            .hkdf_expand(ciphersuite.hash_algorithm(), &prk, &info, len)
            .unwrap()
            .as_slice()
            .to_vec();

        assert_eq!(okm.len(), len);

        teardown(backend).await;
    }

    #[apply(all_storage_types_and_ciphersuites)]
    #[wasm_bindgen_test]
    async fn hash_is_consistent(
        backend: MlsCryptoProvider,
        ciphersuite: Ciphersuite,
        entropy_seed: Option<EntropySeed>,
    ) {
        let backend = backend.await;
        backend.reseed(entropy_seed).unwrap();
        let len = rand::thread_rng().gen_range(LEN_RANGE);
        let data = backend.rand().random_vec(len).unwrap();
        let crypto = backend.crypto();
        let output = crypto.hash(ciphersuite.hash_algorithm(), &data).unwrap();
        let supposed_output_len = ciphersuite.hash_length();
        assert_eq!(output.len(), supposed_output_len);

        teardown(backend).await;
    }

    #[apply(all_storage_types_and_ciphersuites)]
    #[wasm_bindgen_test]
    async fn aead_is_consistent_and_can_roundtrip(
        backend: MlsCryptoProvider,
        ciphersuite: Ciphersuite,
        entropy_seed: Option<EntropySeed>,
    ) {
        let backend = backend.await;
        backend.reseed(entropy_seed).unwrap();
        let len = rand::thread_rng().gen_range(LEN_RANGE);
        let data = backend.rand().random_vec(len).unwrap();
        let aad = backend
            .rand()
            .random_vec(rand::thread_rng().gen_range(LEN_RANGE))
            .unwrap();
        let nonce = backend.rand().random_vec(ciphersuite.aead_nonce_length()).unwrap();
        let key = backend.rand().random_vec(ciphersuite.aead_key_length()).unwrap();

        let crypto = backend.crypto();
        let encrypted = crypto
            .aead_encrypt(ciphersuite.aead_algorithm(), &key, &data, &nonce, &aad)
            .unwrap();

        assert_eq!(encrypted.len(), len + ciphersuite.mac_length());

        let decrypted = crypto
            .aead_decrypt(ciphersuite.aead_algorithm(), &key, &encrypted, &nonce, &aad)
            .unwrap();

        assert_eq!(data, decrypted);

        teardown(backend).await;
    }

    #[apply(all_storage_types_and_ciphersuites)]
    #[wasm_bindgen_test]
    async fn signature_is_consistent(
        backend: MlsCryptoProvider,
        ciphersuite: Ciphersuite,
        entropy_seed: Option<EntropySeed>,
    ) {
        let backend = backend.await;
        backend.reseed(entropy_seed).unwrap();

        let len = rand::thread_rng().gen_range(LEN_RANGE);
        let data = backend.rand().random_vec(len).unwrap();

        let crypto = backend.crypto();
        let (sk, pk) = crypto.signature_key_gen(ciphersuite.signature_algorithm()).unwrap();

        let signature = crypto.sign(ciphersuite.signature_algorithm(), &data, &sk).unwrap();
        crypto
            .verify_signature(ciphersuite.signature_algorithm(), &data, &pk, &signature)
            .unwrap();

        teardown(backend).await;
    }

    #[apply(all_storage_types_and_ciphersuites)]
    #[wasm_bindgen_test]
    async fn hpke_is_consistent(
        backend: MlsCryptoProvider,
        ciphersuite: Ciphersuite,
        entropy_seed: Option<EntropySeed>,
    ) {
        let backend = backend.await;
        backend.reseed(entropy_seed).unwrap();

        let crypto = backend.crypto();

        let message = backend
            .rand()
            .random_vec(rand::thread_rng().gen_range(LEN_RANGE))
            .unwrap();

        let aad = backend
            .rand()
            .random_vec(rand::thread_rng().gen_range(LEN_RANGE))
            .unwrap();

        let info = backend
            .rand()
            .random_vec(rand::thread_rng().gen_range(LEN_RANGE))
            .unwrap();

        let alice = crypto
            .derive_hpke_keypair(
                ciphersuite.hpke_config(),
                &backend
                    .rand()
                    .random_vec(rand::thread_rng().gen_range(LEN_RANGE))
                    .unwrap(),
            )
            .unwrap();

        let secret_message = crypto
            .hpke_seal(ciphersuite.hpke_config(), &alice.public, &info, &aad, &message)
            .unwrap();
        let unsealed_secret_message = crypto
            .hpke_open(ciphersuite.hpke_config(), &secret_message, &alice.private, &info, &aad)
            .unwrap();

        assert_eq!(unsealed_secret_message, message);

        let hpke_info = b"MLS 1.0 external init";

        let (kem, secret_tx) = crypto
            .hpke_setup_sender_and_export(
                ciphersuite.hpke_config(),
                &alice.public,
                &info,
                hpke_info,
                ciphersuite.hash_length(),
            )
            .unwrap();

        let secret_rx = crypto
            .hpke_setup_receiver_and_export(
                ciphersuite.hpke_config(),
                &kem,
                &alice.private,
                &info,
                hpke_info,
                ciphersuite.hash_length(),
            )
            .unwrap();

        assert_eq!(*secret_tx, *secret_rx);

        teardown(backend).await;
    }
}
