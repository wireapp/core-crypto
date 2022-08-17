use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion,
};
use futures_lite::future::block_on;

use core_crypto::{
    prelude::{CertificateBundle, MlsProposal},
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

fn add_commmit_bench(c: &mut Criterion) {
    for (case, ciphersuite, credential) in working_test_cases() {
        let mut group = c.benchmark_group(format!("Commit add ({})", case));
        for i in (GROUP_MIN..GROUP_MAX).step_by(GROUP_STEP) {
            group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup(&ciphersuite, &credential);
                        add_clients(&mut central, &id, &ciphersuite, *i);
                        let member = rand_member(&ciphersuite);
                        (central, id, member)
                    },
                    |(mut central, id, member)| async move {
                        black_box(central.add_members_to_conversation(&id, &mut [member]).await.unwrap());
                        black_box(central.commit_accepted(&id).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

fn remove_commit_bench(c: &mut Criterion) {
    for (case, ciphersuite, credential) in working_test_cases() {
        let mut group = c.benchmark_group(format!("Commit remove ({})", case));
        for i in (GROUP_MIN..GROUP_MAX).step_by(GROUP_STEP) {
            group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup(&ciphersuite, &credential);
                        let client_ids = add_clients(&mut central, &id, &ciphersuite, *i);
                        (central, id, client_ids)
                    },
                    |(mut central, id, client_ids)| async move {
                        black_box(
                            central
                                .remove_members_from_conversation(&id, client_ids.as_slice())
                                .await
                                .unwrap(),
                        );
                        black_box(central.commit_accepted(&id).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

fn update_commit_bench(c: &mut Criterion) {
    for (case, ciphersuite, credential) in working_test_cases() {
        let mut group = c.benchmark_group(format!("Commit update ({})", case));
        for i in (GROUP_MIN..GROUP_MAX).step_by(GROUP_STEP) {
            group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup(&ciphersuite, &credential);
                        add_clients(&mut central, &id, &ciphersuite, *i);
                        (central, id)
                    },
                    |(mut central, id)| async move {
                        black_box(central.update_keying_material(&id).await.unwrap());
                        black_box(central.commit_accepted(&id).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

// pending proposal constants
const PENDING_MAX: usize = 101;
const PENDING_MIN: usize = 1;
const PENDING_STEP: usize = 20;

fn commit_pending_proposals_bench_var_pending(c: &mut Criterion) {
    for (case, ciphersuite, credential) in working_test_cases() {
        let mut group = c.benchmark_group(format!("Commit pending proposals var(pending size) ({})", case));
        for i in (PENDING_MIN..PENDING_MAX).step_by(PENDING_STEP) {
            group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup(&ciphersuite, &credential);
                        add_clients(&mut central, &id, &ciphersuite, GROUP_MAX);
                        block_on(async {
                            for _ in 0..*i {
                                let (kp, ..) = rand_key_package(&ciphersuite);
                                central.new_proposal(&id, MlsProposal::Add(kp)).await.unwrap();
                            }
                        });
                        (central, id)
                    },
                    |(mut central, id)| async move {
                        black_box(central.commit_pending_proposals(&id).await.unwrap());
                        black_box(central.commit_accepted(&id).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

fn commit_pending_proposals_bench_var_group_size(c: &mut Criterion) {
    for (case, ciphersuite, credential) in working_test_cases() {
        let mut group = c.benchmark_group(format!("Commit pending proposals var(group size) ({})", case));
        for i in (GROUP_MIN..GROUP_MAX).step_by(GROUP_STEP) {
            group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup(&ciphersuite, &credential);
                        add_clients(&mut central, &id, &ciphersuite, *i);
                        block_on(async {
                            for _ in 0..PENDING_MAX {
                                let (kp, ..) = rand_key_package(&ciphersuite);
                                central.new_proposal(&id, MlsProposal::Add(kp)).await.unwrap();
                            }
                        });
                        (central, id)
                    },
                    |(mut central, id)| async move {
                        black_box(central.commit_pending_proposals(&id).await.unwrap());
                        black_box(central.commit_accepted(&id).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

criterion_group!(
    name = commit;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = add_commmit_bench, remove_commit_bench, update_commit_bench, commit_pending_proposals_bench_var_pending, commit_pending_proposals_bench_var_group_size
);
criterion_main!(commit);
