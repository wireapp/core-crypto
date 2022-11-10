use criterion::{async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize, Criterion};
use futures_lite::future::block_on;
use rand::distributions::{Alphanumeric, DistString};

use crate::utils::*;

#[path = "utils/mod.rs"]
mod utils;

fn encryption_bench_var_group_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("Encrypt f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
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
    }
    group.finish();
}

fn encryption_bench_var_msg_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("Encrypt f(msg size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (MSG_RANGE).step_by(MSG_STEP) {
            group.bench_with_input(case.benchmark_id(i, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        add_clients(&mut central, &id, ciphersuite, GROUP_MAX);
                        let text = Alphanumeric.sample_string(&mut rand::thread_rng(), *i);
                        (central, id, text)
                    },
                    |(mut central, id, text)| async move {
                        black_box(central.encrypt_message(&id, text).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn decryption_bench_var_msg_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("Decrypt f(msg size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (MSG_RANGE).step_by(MSG_STEP) {
            group.bench_with_input(case.benchmark_id(i, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut alice_central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        let (mut bob_central, ..) = new_central(ciphersuite, &credential, in_memory);
                        invite(&mut alice_central, &mut bob_central, &id);

                        let text = Alphanumeric.sample_string(&mut rand::thread_rng(), *i);
                        let encrypted = block_on(async { alice_central.encrypt_message(&id, text).await.unwrap() });
                        (bob_central, id, encrypted)
                    },
                    |(mut central, id, encrypted)| async move {
                        black_box(central.decrypt_message(&id, encrypted).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

criterion_group!(
    name = encryption;
    config = criterion();
    targets =
    encryption_bench_var_group_size,
    encryption_bench_var_msg_size,
    decryption_bench_var_msg_size,
);
criterion_main!(encryption);
