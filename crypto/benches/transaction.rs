use criterion::async_executor::FuturesExecutor;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use openmls_traits::types::Ciphersuite;
use rand::distributions::{Alphanumeric, DistString};

pub mod utils;

use utils::*;
fn decrypt_transaction(c: &mut Criterion) {
    const MESSAGE_LENGTH: usize = 100;
    const MESSAGE_COUNT: usize = 1000;

    let mut group = c.benchmark_group(format!("Decrypting {MESSAGE_COUNT} messages of {MESSAGE_LENGTH} bytes"));
    let (ciphersuite, credential, in_memory) = (
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.into(),
        None,
        false,
    );

    for transactional in [true, false] {
        let id = if transactional {
            "transactional"
        } else {
            "non-transactional"
        };
        group.bench_with_input(id, &transactional, |b, transactional| {
            b.to_async(FuturesExecutor).iter_batched(
                || {
                    async_std::task::block_on(async {
                        let (mut alice_central, id, delivery_service) =
                            setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
                        let (mut bob_central, ..) = new_central(ciphersuite, credential.as_ref(), in_memory).await;
                        invite(&mut alice_central, &mut bob_central, &id, ciphersuite, delivery_service).await;

                        let context = alice_central.new_transaction().await.unwrap();
                        let mut encrypted_messages: Vec<Vec<u8>> = vec![];
                        for _ in 0..MESSAGE_COUNT {
                            let text = Alphanumeric.sample_string(&mut rand::thread_rng(), MESSAGE_LENGTH);
                            encrypted_messages.push(
                                context
                                    .conversation_guard(&id)
                                    .await
                                    .unwrap()
                                    .encrypt_message(text)
                                    .await
                                    .unwrap(),
                            );
                        }
                        context.finish().await.unwrap();
                        (bob_central, id, encrypted_messages, transactional)
                    })
                },
                |(bob_central, id, encrypted_messages, transactional)| async move {
                    if *transactional {
                        let context = bob_central.new_transaction().await.unwrap();
                        for message in encrypted_messages.into_iter() {
                            context
                                .conversation_guard(&id)
                                .await
                                .unwrap()
                                .decrypt_message(message)
                                .await
                                .unwrap();
                        }
                        context.finish().await.unwrap();
                    } else {
                        for message in encrypted_messages.into_iter() {
                            let context = bob_central.new_transaction().await.unwrap();
                            context
                                .conversation_guard(&id)
                                .await
                                .unwrap()
                                .decrypt_message(message)
                                .await
                                .unwrap();
                            context.finish().await.unwrap();
                        }
                    }
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group!(
    name = decryption;
    config = criterion();
    targets = decrypt_transaction,
);
criterion_main!(decryption);
