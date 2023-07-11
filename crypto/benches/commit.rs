use criterion::{
    async_executor::AsyncStdExecutor as FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize,
    Criterion,
};

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
                        async_std::task::block_on(async {
                            let (mut central, id) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
                            add_clients(&mut central, &id, ciphersuite, *i).await;
                            let member = rand_member(ciphersuite).await;
                            (central, id, member)
                        })
                    },
                    |(mut central, id, member)| async move {
                        black_box(central.add_members_to_conversation(&id, &mut [member]).await.unwrap());
                        central.commit_accepted(&id).await.unwrap();
                        black_box(());
                    },
                    BatchSize::LargeInput,
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
                        async_std::task::block_on(async {
                            let (central, id) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
                            let mut members = Vec::new();
                            for _ in 0..*i {
                                members.push(rand_member(ciphersuite).await);
                            }
                            (central, id, members)
                        })
                    },
                    |(mut central, id, mut members)| async move {
                        black_box(
                            central
                                .add_members_to_conversation(&id, members.as_mut_slice())
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
                        async_std::task::block_on(async {
                            let (mut central, id) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
                            let (client_ids, ..) = add_clients(&mut central, &id, ciphersuite, *i).await;
                            (central, id, client_ids)
                        })
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
                        async_std::task::block_on(async {
                            let (mut central, id) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
                            let (client_ids, ..) = add_clients(&mut central, &id, ciphersuite, GROUP_MAX).await;
                            let to_remove = client_ids[..*i].to_vec();
                            (central, id, to_remove)
                        })
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
                        async_std::task::block_on(async {
                            let (mut central, id) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
                            add_clients(&mut central, &id, ciphersuite, *i).await;
                            (central, id)
                        })
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
                        async_std::task::block_on(async {
                            let (mut central, id) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
                            add_clients(&mut central, &id, ciphersuite, GROUP_MAX).await;

                            for _ in 0..*i {
                                let (kp, ..) = rand_key_package(ciphersuite).await;
                                central.new_add_proposal(&id, kp).await.unwrap();
                            }

                            (central, id)
                        })
                    },
                    |(mut central, id)| async move {
                        black_box(central.commit_pending_proposals(&id).await.unwrap());
                        central.commit_accepted(&id).await.unwrap();
                        black_box(());
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
                        async_std::task::block_on(async {
                            let (mut central, id) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
                            add_clients(&mut central, &id, ciphersuite, *i).await;
                            for _ in 0..PENDING_MAX {
                                let (kp, ..) = rand_key_package(ciphersuite).await;
                                central.new_add_proposal(&id, kp).await.unwrap();
                            }
                            (central, id)
                        })
                    },
                    |(mut central, id)| async move {
                        black_box(central.commit_pending_proposals(&id).await.unwrap());
                        central.commit_accepted(&id).await.unwrap();
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
