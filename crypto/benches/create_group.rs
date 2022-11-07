use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion,
};
use futures_lite::future::block_on;
use openmls::prelude::VerifiablePublicGroupState;

use core_crypto::prelude::{ConversationMember, MlsConversationConfiguration, MlsConversationInitBundle};

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
                        let (central, ..) = new_central(*ciphersuite, &credential, in_memory);
                        let id = conversation_id();
                        let cfg = MlsConversationConfiguration {
                            ciphersuite: *ciphersuite,
                            ..Default::default()
                        };
                        (central, id, cfg)
                    },
                    |(mut central, id, cfg)| async move {
                        black_box(central.new_conversation(id, cfg).await.unwrap());
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
                        let (mut alice_central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        add_clients(&mut alice_central, &id, ciphersuite, *i);

                        let (bob_central, ..) = new_central(ciphersuite, &credential, in_memory);
                        let bob_kpbs = block_on(async { bob_central.client_keypackages(1).await.unwrap() });
                        let bob_kp = bob_kpbs.first().unwrap().key_package().clone();
                        let bob_member = ConversationMember::new(bob_central.client_id().unwrap(), bob_kp);
                        let welcome = block_on(async {
                            alice_central
                                .add_members_to_conversation(&id, &mut [bob_member])
                                .await
                                .unwrap()
                                .welcome
                        });
                        let cfg = MlsConversationConfiguration {
                            ciphersuite: ciphersuite.clone(),
                            ..Default::default()
                        };
                        (bob_central, welcome, cfg)
                    },
                    |(mut central, welcome, cfg)| async move {
                        black_box(central.process_welcome_message(welcome, cfg).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn join_from_public_group_state_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Join from external commit f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        use openmls::prelude::TlsDeserializeTrait as _;
                        let (mut alice_central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        add_clients(&mut alice_central, &id, ciphersuite, *i);
                        let pgs = block_on(async { alice_central.export_public_group_state(&id).await.unwrap() });
                        let pgs: VerifiablePublicGroupState =
                            VerifiablePublicGroupState::tls_deserialize(&mut pgs.as_slice()).unwrap();
                        let (bob_central, ..) = new_central(ciphersuite, &credential, in_memory);
                        let cfg = MlsConversationConfiguration {
                            ciphersuite: ciphersuite.clone(),
                            ..Default::default()
                        };
                        (bob_central, pgs, cfg)
                    },
                    |(mut central, pgs, cfg)| async move {
                        let MlsConversationInitBundle { conversation_id, .. } = black_box(
                            central
                                .join_by_external_commit(pgs, MlsConversationConfiguration::default())
                                .await
                                .unwrap(),
                        );
                        black_box(
                            central
                                .merge_pending_group_from_external_commit(&conversation_id, cfg)
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

criterion_group!(
    name = create_group;
    config = criterion();
    targets =
    create_group_bench,
    join_from_welcome_bench,
    join_from_public_group_state_bench,
);
criterion_main!(create_group);
