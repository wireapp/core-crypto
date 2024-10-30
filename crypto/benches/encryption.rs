use criterion::{
    async_executor::AsyncStdExecutor as FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize,
    Criterion,
};
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
                        async_std::task::block_on(async {
                            let (mut central, id) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
                            add_clients(&mut central, &id, ciphersuite, *i).await;
                            let text = Alphanumeric.sample_string(&mut rand::thread_rng(), MSG_MAX);
                            (central, id, text)
                        })
                    },
                    |(central, id, text)| async move {
                        let context = central.new_transaction().await.unwrap();
                        black_box(context.encrypt_message(&id, text).await.unwrap());
                        context.finish().await.unwrap();
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
                        async_std::task::block_on(async {
                            let (mut central, id) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
                            add_clients(&mut central, &id, ciphersuite, GROUP_MAX).await;
                            let text = Alphanumeric.sample_string(&mut rand::thread_rng(), *i);
                            (central, id, text)
                        })
                    },
                    |(central, id, text)| async move {
                        let context = central.new_transaction().await.unwrap();
                        black_box(context.encrypt_message(&id, text).await.unwrap());
                        context.finish().await.unwrap();
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
                        async_std::task::block_on(async {
                            let (mut alice_central, id) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
                            let (mut bob_central, ..) = new_central(ciphersuite, credential.as_ref(), in_memory).await;
                            invite(&mut alice_central, &mut bob_central, &id, ciphersuite).await;

                            let context = alice_central.new_transaction().await.unwrap();
                            let text = Alphanumeric.sample_string(&mut rand::thread_rng(), *i);
                            let encrypted = context.encrypt_message(&id, text).await.unwrap();
                            context.finish().await.unwrap();
                            (bob_central, id, encrypted)
                        })
                    },
                    |(central, id, encrypted)| async move {
                        let context = central.new_transaction().await.unwrap();
                        black_box(context.decrypt_message(&id, encrypted).await.unwrap());
                        context.finish().await.unwrap();
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
