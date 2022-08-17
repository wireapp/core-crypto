use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion,
};
use futures_lite::future::block_on;
use openmls::prelude::VerifiablePublicGroupState;

use core_crypto::{
    prelude::{CertificateBundle, ConversationMember, MlsConversationConfiguration},
    MlsCiphersuite,
};

use crate::utils::*;

#[path = "utils.rs"]
mod utils;

// FIXME: currently operations do not work for other ciphersuites
fn working_test_cases() -> impl Iterator<Item = (MlsTestCase, MlsCiphersuite, Option<CertificateBundle>)> {
    MlsTestCase::values().filter(|(c, ..)| match c {
        MlsTestCase::Basic_Ciphersuite1 => true,
        _ => false,
    })
}

fn create_group_bench(c: &mut Criterion) {
    for (case, ciphersuite, credential) in working_test_cases() {
        let mut group = c.benchmark_group("Create group");
        group.bench_with_input(BenchmarkId::from_parameter(case), &ciphersuite, |b, ciphersuite| {
            b.to_async(FuturesExecutor).iter_batched(
                || {
                    let (central, ..) = new_central(&credential);
                    let id = conversation_id();
                    let cfg = MlsConversationConfiguration {
                        ciphersuite: ciphersuite.clone(),
                        ..Default::default()
                    };
                    (central, id, cfg)
                },
                |(mut central, id, cfg)| async move {
                    black_box(central.new_conversation(id, cfg).await.unwrap());
                },
                BatchSize::SmallInput,
            )
        });
        group.finish();
    }
}

fn join_from_welcome_bench(c: &mut Criterion) {
    for (case, ciphersuite, credential) in working_test_cases() {
        let mut group = c.benchmark_group(format!("Create group from welcome ({})", case));
        for i in (GROUP_MIN..GROUP_MAX).step_by(GROUP_STEP) {
            group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut alice_central, id) = setup(&ciphersuite, &credential);
                        add_clients(&mut alice_central, &id, &ciphersuite, *i);

                        let (bob_central, ..) = new_central(&credential);
                        let bob_kpbs = block_on(async { bob_central.client_keypackages(1).await.unwrap() });
                        let bob_kp = bob_kpbs.first().unwrap().key_package().clone();
                        let bob_member = ConversationMember::new(bob_central.client_id(), bob_kp);
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
        group.finish();
    }
}

fn join_from_public_group_state_bench(c: &mut Criterion) {
    for (case, ciphersuite, credential) in working_test_cases() {
        let mut group = c.benchmark_group(format!("Create group from PublicGroupState ({})", case));
        for i in (GROUP_MIN..GROUP_MAX).step_by(GROUP_STEP) {
            group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        use openmls::prelude::TlsDeserializeTrait as _;
                        let (mut alice_central, id) = setup(&ciphersuite, &credential);
                        add_clients(&mut alice_central, &id, &ciphersuite, *i);
                        let pgs = block_on(async { alice_central.export_public_group_state(&id).await.unwrap() });
                        let pgs: VerifiablePublicGroupState =
                            VerifiablePublicGroupState::tls_deserialize(&mut pgs.as_slice()).unwrap();
                        let (bob_central, ..) = new_central(&credential);
                        let cfg = MlsConversationConfiguration {
                            ciphersuite: ciphersuite.clone(),
                            ..Default::default()
                        };
                        (bob_central, pgs, cfg)
                    },
                    |(mut central, pgs, cfg)| async move {
                        let (group_id, ..) = black_box(central.join_by_external_commit(pgs).await.unwrap());
                        black_box(
                            central
                                .merge_pending_group_from_external_commit(group_id.as_slice(), cfg)
                                .await
                                .unwrap(),
                        );
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

criterion_group!(
    name = create_group;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = create_group_bench, join_from_welcome_bench, join_from_public_group_state_bench
);
criterion_main!(create_group);
