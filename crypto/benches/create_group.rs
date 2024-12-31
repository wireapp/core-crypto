use criterion::{
    async_executor::AsyncStdExecutor as FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize,
    BenchmarkId, Criterion,
};

use core_crypto::prelude::{MlsConversationConfiguration, MlsCredentialType, MlsCustomConfiguration};

use crate::utils::*;

#[path = "utils/mod.rs"]
mod utils;

/// Benchmark to measure the runtime of creating a group.
fn create_group_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Create group");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        group.bench_with_input(
            BenchmarkId::from_parameter(case.ciphersuite_name(in_memory)),
            &ciphersuite,
            |b, ciphersuite| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        async_std::task::block_on(async {
                            let (central, ..) = new_central(*ciphersuite, credential.as_ref(), in_memory).await;
                            let id = conversation_id();
                            let cfg = MlsConversationConfiguration {
                                ciphersuite: *ciphersuite,
                                ..Default::default()
                            };
                            (central, id, cfg)
                        })
                    },
                    |(central, id, cfg)| async move {
                        let context = central.new_transaction().await.unwrap();
                        context
                            .new_conversation(&id, MlsCredentialType::Basic, cfg)
                            .await
                            .unwrap();
                        context.finish().await.unwrap();
                        black_box(());
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
    group.finish();
}

/// Benchmark to measure the impact of group size on the runtime of joining a group from a welcome message.
fn join_from_welcome_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Join from welcome f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        async_std::task::block_on(async {
                            let (alice_central, id, _, _, delivery_service) =
                                setup_mls_and_add_clients(ciphersuite, credential.as_ref(), in_memory, *i).await;

                            let (bob_central, ..) = new_central(ciphersuite, credential.as_ref(), in_memory).await;
                            let bob_context = bob_central.new_transaction().await.unwrap();
                            let bob_kpbs = bob_context
                                .get_or_create_client_keypackages(ciphersuite, MlsCredentialType::Basic, 1)
                                .await
                                .unwrap();
                            let bob_kp = bob_kpbs.first().unwrap().clone();
                            bob_context.finish().await.unwrap();
                            let alice_context = alice_central.new_transaction().await.unwrap();
                            alice_context
                                .add_members_to_conversation(&id, vec![bob_kp.into()])
                                .await
                                .unwrap();
                            let welcome = delivery_service.latest_welcome_message().await;
                            alice_context.finish().await.unwrap();
                            (bob_central, welcome)
                        })
                    },
                    |(central, welcome)| async move {
                        let context = central.new_transaction().await.unwrap();
                        black_box(
                            context
                                .process_welcome_message(welcome.into(), MlsCustomConfiguration::default())
                                .await
                                .unwrap(),
                        );
                        context.finish().await.unwrap();
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

/// Benchmark to measure the impact of group size on the runtime of joining a group via an external commit.
fn join_from_group_info_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Join from external commit f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        async_std::task::block_on(async {
                            let (_, _, _, group_info, ..) =
                                setup_mls_and_add_clients(ciphersuite, credential.as_ref(), in_memory, *i).await;
                            let (bob_central, ..) = new_central(ciphersuite, credential.as_ref(), in_memory).await;
                            (bob_central, group_info)
                        })
                    },
                    |(central, group_info)| async move {
                        let context = central.new_transaction().await.unwrap();
                        black_box(
                            context
                                .join_by_external_commit(
                                    group_info,
                                    MlsCustomConfiguration::default(),
                                    MlsCredentialType::Basic,
                                )
                                .await
                                .unwrap(),
                        );
                        context.finish().await.unwrap();
                        black_box(());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

criterion_group!(
    name = create_group;
    config = criterion();
    targets =
    create_group_bench,
    join_from_welcome_bench,
    join_from_group_info_bench,
);
criterion_main!(create_group);
