use criterion::{async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize, Criterion};
use futures_lite::future::block_on;

use core_crypto::prelude::{ConversationMember, MlsProposal};

use crate::utils::*;

#[path = "utils/mod.rs"]
mod utils;

fn commit_add_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Commit add f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        add_clients(&mut central, &id, ciphersuite, *i);
                        let member = rand_member(ciphersuite);
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
    }
    group.finish();
}

fn commit_add_n_clients_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Commit add f(number clients)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        let members = (0..*i)
                            .map(|_| rand_member(ciphersuite))
                            .collect::<Vec<ConversationMember>>();
                        (central, id, members)
                    },
                    |(mut central, id, mut members)| async move {
                        black_box(
                            central
                                .add_members_to_conversation(&id, members.as_mut_slice())
                                .await
                                .unwrap(),
                        );
                        black_box(central.commit_accepted(&id).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn commit_remove_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Commit remove f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        let client_ids = add_clients(&mut central, &id, ciphersuite, *i);
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
    }
    group.finish();
}

fn commit_remove_n_clients_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Commit remove f(number clients)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        let client_ids = add_clients(&mut central, &id, ciphersuite, GROUP_MAX);
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
                        black_box(central.commit_accepted(&id).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn commit_update_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Commit update f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        add_clients(&mut central, &id, ciphersuite, *i);
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
    }
    group.finish();
}

fn commit_pending_proposals_bench_var_n_proposals(c: &mut Criterion) {
    let mut group = c.benchmark_group("Commit pending proposals f(pending size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (PENDING_RANGE).step_by(PENDING_STEP) {
            group.bench_with_input(case.benchmark_id(i, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        add_clients(&mut central, &id, ciphersuite, GROUP_MAX);
                        block_on(async {
                            for _ in 0..*i {
                                let (kp, ..) = rand_key_package(ciphersuite);
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
    }
    group.finish();
}

fn commit_pending_proposals_bench_var_group_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("Commit pending proposals f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        add_clients(&mut central, &id, ciphersuite, *i);
                        block_on(async {
                            for _ in 0..PENDING_MAX {
                                let (kp, ..) = rand_key_package(ciphersuite);
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
    }
    group.finish();
}

criterion_group!(
    name = commit;
    config = criterion();
    targets =
    commit_add_bench,
    commit_add_n_clients_bench,
    commit_remove_bench,
    commit_remove_n_clients_bench,
    commit_update_bench,
    commit_pending_proposals_bench_var_n_proposals,
    commit_pending_proposals_bench_var_group_size,
);
criterion_main!(commit);
