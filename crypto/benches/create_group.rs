use criterion::{
    async_executor::AsyncStdExecutor as FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize,
    BenchmarkId, Criterion,
};

use core_crypto::prelude::{
    ConversationMember, MlsConversationConfiguration, MlsConversationInitBundle, MlsCredentialType,
    MlsCustomConfiguration,
};

use crate::utils::*;

#[path = "utils/mod.rs"]
mod utils;

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
                    |(mut central, id, cfg)| async move {
                        central
                            .new_conversation(&id, MlsCredentialType::Basic, cfg)
                            .await
                            .unwrap();
                        black_box(());
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
    group.finish();
}

fn join_from_welcome_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Join from welcome f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        async_std::task::block_on(async {
                            let (mut alice_central, id) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
                            add_clients(&mut alice_central, &id, ciphersuite, *i).await;

                            let (bob_central, ..) = new_central(ciphersuite, credential.as_ref(), in_memory).await;
                            let bob_kpbs = bob_central
                                .get_or_create_client_keypackages(ciphersuite, MlsCredentialType::Basic, 1)
                                .await
                                .unwrap();
                            let bob_kp = bob_kpbs.first().unwrap().clone();
                            let bob_member = ConversationMember::new(bob_central.client_id().unwrap(), bob_kp);
                            let welcome = alice_central
                                .add_members_to_conversation(&id, &mut [bob_member])
                                .await
                                .unwrap()
                                .welcome;
                            (bob_central, welcome)
                        })
                    },
                    |(mut central, welcome)| async move {
                        black_box(
                            central
                                .process_welcome_message(welcome.into(), MlsCustomConfiguration::default())
                                .await
                                .unwrap(),
                        );
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn join_from_group_info_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Join from external commit f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        async_std::task::block_on(async {
                            let (mut alice_central, id) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
                            let (_, group_info) = add_clients(&mut alice_central, &id, ciphersuite, *i).await;
                            let (bob_central, ..) = new_central(ciphersuite, credential.as_ref(), in_memory).await;
                            (bob_central, group_info)
                        })
                    },
                    |(mut central, group_info)| async move {
                        let MlsConversationInitBundle { conversation_id, .. } = black_box(
                            central
                                .join_by_external_commit(
                                    group_info,
                                    MlsCustomConfiguration::default(),
                                    MlsCredentialType::Basic,
                                )
                                .await
                                .unwrap(),
                        );
                        central
                            .merge_pending_group_from_external_commit(&conversation_id)
                            .await
                            .unwrap();
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
