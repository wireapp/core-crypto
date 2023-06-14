use crate::utils::*;
use core_crypto::mls::MlsCiphersuite;
use core_crypto::prelude::CertificateBundle;
use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion,
};
use futures_lite::future::block_on;
use proteus::keys;
use proteus::keys::{PreKey, PreKeyBundle};
use rand::distributions::{Alphanumeric, DistString};

#[path = "utils/mod.rs"]
mod utils;

fn mls_cases() -> Vec<(MlsCiphersuite, Option<CertificateBundle>, bool, &'static str)> {
    // Ciphersuite 3 is the closest to proteus one
    const CIPHERSUITE: MlsTestCase = MlsTestCase::Basic_Ciphersuite3;
    let (_, ciphersuite, credential) = CIPHERSUITE.get();
    let in_memory = (ciphersuite, credential.clone(), true, "MLS/mem");
    let in_db = (ciphersuite, credential, false, "MLS/db");
    if cfg!(feature = "bench-in-db") {
        vec![in_memory, in_db]
    } else {
        vec![in_memory]
    }
}

fn proteus_cases() -> Vec<(bool, &'static str)> {
    let in_memory = (true, "Proteus/mem");
    let in_db = (false, "Proteus/db");
    if cfg!(feature = "bench-in-db") {
        vec![in_memory, in_db]
    } else {
        vec![in_memory]
    }
}

fn encrypt_message_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Mls vs Proteus: encrypt");
    for i in (GROUP_RANGE).step_by(GROUP_STEP) {
        // MLS
        for (ciphersuite, credential, in_memory, bench_name) in mls_cases() {
            group.bench_with_input(BenchmarkId::new(bench_name, i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        add_clients(&mut central, &id, ciphersuite, *i);
                        let text = Alphanumeric.sample_string(&mut rand::thread_rng(), MSG_MAX);
                        (central, id, text)
                    },
                    |(mut central, id, text)| async move {
                        black_box(central.encrypt_message(&id, text).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        // Proteus
        for (in_memory, bench_name) in proteus_cases() {
            group.bench_with_input(BenchmarkId::new(bench_name, i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, keystore) = setup_proteus(in_memory);
                        let session_material = (0..*i)
                            .map(|_| (session_id(), new_prekey().serialise().unwrap()))
                            .collect::<Vec<(String, Vec<u8>)>>();
                        for (session_id, key) in &session_material {
                            block_on(async {
                                central.session_from_prekey(session_id, key).await.unwrap();
                            });
                        }
                        let text = Alphanumeric.sample_string(&mut rand::thread_rng(), MSG_MAX);
                        (central, keystore, session_material, text)
                    },
                    |(mut central, mut keystore, session_material, text)| async move {
                        for (session_id, _) in session_material {
                            black_box(
                                central
                                    .encrypt(&mut keystore, &session_id, text.as_bytes())
                                    .await
                                    .unwrap(),
                            );
                        }
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn add_client_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Mls vs Proteus: add");
    for i in (GROUP_RANGE).step_by(GROUP_STEP) {
        // MLS
        for (ciphersuite, credential, in_memory, bench_name) in mls_cases() {
            group.bench_with_input(BenchmarkId::new(bench_name, i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        add_clients(&mut central, &id, ciphersuite, *i);
                        let member = block_on(async { rand_member(ciphersuite).await });
                        (central, id, member)
                    },
                    |(mut central, id, member)| async move {
                        black_box(central.add_members_to_conversation(&id, &mut [member]).await.unwrap());
                        central.commit_accepted(&id).await.unwrap();
                        black_box(());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        // Proteus
        // From proteus POV, adding 1 client in a group of N means adding N times 1 client to N central
        // To simplify we are just going to add N times a client to just 1 central
        for (in_memory, bench_name) in proteus_cases() {
            group.bench_with_input(BenchmarkId::new(bench_name, i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (central, keystore) = setup_proteus(in_memory);
                        let session_material = (0..*i)
                            .map(|_| (session_id(), new_prekey().serialise().unwrap()))
                            .collect::<Vec<(String, Vec<u8>)>>();
                        (central, keystore, session_material)
                    },
                    |(mut central, _keystore, session_material)| async move {
                        for (session_id, key) in session_material {
                            black_box(central.session_from_prekey(&session_id, &key).await.unwrap());
                        }
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn remove_client_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Mls vs Proteus: remove");
    for i in (GROUP_RANGE).step_by(GROUP_STEP) {
        // MLS
        for (ciphersuite, credential, in_memory, bench_name) in mls_cases() {
            group.bench_with_input(BenchmarkId::new(bench_name, i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        let (client_ids, ..) = add_clients(&mut central, &id, ciphersuite, GROUP_MAX);
                        let to_remove = client_ids[..*i].to_vec();
                        (central, id, to_remove)
                    },
                    |(mut central, id, client_ids)| async move {
                        black_box(
                            central
                                .remove_members_from_conversation(&id, client_ids.as_slice())
                                .await
                                .unwrap(),
                        );
                        central.commit_accepted(&id).await.unwrap();
                        black_box(());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        // Proteus
        // From proteus POV, removing 1 client from a group of N means removing N times 1 client from N central
        // To simplify we are just going to remove N times a client from just 1 central
        for (in_memory, bench_name) in proteus_cases() {
            group.bench_with_input(BenchmarkId::new(bench_name, i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, keystore) = setup_proteus(in_memory);
                        let session_material = (0..*i)
                            .map(|_| (session_id(), new_prekey().serialise().unwrap()))
                            .collect::<Vec<(String, Vec<u8>)>>();
                        for (session_id, key) in &session_material {
                            block_on(async {
                                central.session_from_prekey(session_id, key).await.unwrap();
                            });
                        }
                        (central, keystore, session_material)
                    },
                    |(mut central, keystore, session_material)| async move {
                        for (session_id, _) in session_material {
                            central.session_delete(&keystore, &session_id).await.unwrap();
                            black_box(());
                        }
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn update_client_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Mls vs Proteus: update");
    for i in (GROUP_RANGE).step_by(GROUP_STEP) {
        // MLS
        for (ciphersuite, credential, in_memory, bench_name) in mls_cases() {
            group.bench_with_input(BenchmarkId::new(bench_name, i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        add_clients(&mut central, &id, ciphersuite, *i);
                        (central, id)
                    },
                    |(mut central, id)| async move {
                        black_box(central.update_keying_material(&id).await.unwrap());
                        central.commit_accepted(&id).await.unwrap();
                        black_box(());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        // Proteus
        // From proteus POV, adding 1 client in a group of N means adding N times 1 client to N central
        // To simplify we are just going to add N times a client to just 1 central
        for (in_memory, bench_name) in proteus_cases() {
            group.bench_with_input(BenchmarkId::new(bench_name, i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, keystore) = setup_proteus(in_memory);
                        let session_material = (0..*i)
                            .map(|_| (session_id(), new_prekey().serialise().unwrap()))
                            .collect::<Vec<(String, Vec<u8>)>>();
                        for (session_id, key) in &session_material {
                            block_on(async {
                                central.session_from_prekey(session_id, key).await.unwrap();
                            });
                        }
                        let new_pkb = black_box(
                            PreKeyBundle::new(
                                keys::IdentityKeyPair::new().public_key,
                                &PreKey::new(keys::PreKeyId::new(2)),
                            )
                            .serialise()
                            .unwrap(),
                        );
                        (central, keystore, new_pkb, session_material)
                    },
                    |(mut central, keystore, new_pkb, session_material)| async move {
                        for (session_id, _) in session_material {
                            // replace existing session
                            central.session_delete(&keystore, &session_id).await.unwrap();
                            black_box(());
                            black_box(central.session_from_prekey(&session_id, &new_pkb).await.unwrap());
                        }
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

criterion_group!(
    name = mls_vs_proteus;
    config = criterion();
    targets =
    encrypt_message_bench,
    add_client_bench,
    remove_client_bench,
    update_client_bench,
);
criterion_main!(mls_vs_proteus);
