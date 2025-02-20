/// Benchmarks related to commit creation.
/// We're measuring the impact of different parameters on the runtime.
use criterion::{
    async_executor::AsyncStdExecutor as FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize,
    Criterion,
};

use crate::utils::*;

#[path = "utils/mod.rs"]
mod utils;

/// Benchmark to measure the impact of group size on the runtime of creating and merging an add commit.
fn commit_add_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Commit add f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        async_std::task::block_on(async {
                            let (central, id, ..) =
                                setup_mls_and_add_clients(ciphersuite, credential.as_ref(), in_memory, *i).await;
                            let (kp, _) = rand_key_package(ciphersuite).await;
                            (central, id, vec![kp.into()])
                        })
                    },
                    |(central, id, kps)| async move {
                        let context = central.new_transaction().await.unwrap();
                        black_box(
                            context
                                .conversation_guard(&id)
                                .await
                                .unwrap()
                                .add_members(kps)
                                .await
                                .unwrap(),
                        );
                        context.finish().await.unwrap();
                        black_box(());
                    },
                    BatchSize::LargeInput,
                )
            });
        }
    }
    group.finish();
}

/// Benchmark to measure impact of client count in an add commit on the runtime of commit creation and merging.
fn commit_add_n_clients_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Commit add f(number clients)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        async_std::task::block_on(async {
                            let (central, id, _) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
                            let mut kps = Vec::with_capacity(*i);
                            for _ in 0..*i {
                                let (kp, _) = rand_key_package(ciphersuite).await;
                                kps.push(kp.into());
                            }
                            (central, id, kps)
                        })
                    },
                    |(central, id, kps)| async move {
                        let context = central.new_transaction().await.unwrap();
                        black_box(
                            context
                                .conversation_guard(&id)
                                .await
                                .unwrap()
                                .add_members(kps)
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

/// Benchmark to measure the impact of group size on the runtime of creating and merging a remove commit.
/// Number of removed clients is equal to group size (→ all clients except the initial client from [setup_mls] are removed).
fn commit_remove_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Commit remove f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        async_std::task::block_on(async {
                            let (central, id, client_ids, ..) =
                                setup_mls_and_add_clients(ciphersuite, credential.as_ref(), in_memory, *i).await;
                            (central, id, client_ids)
                        })
                    },
                    |(central, id, client_ids)| async move {
                        let context = central.new_transaction().await.unwrap();
                        black_box(
                            context
                                .conversation_guard(&id)
                                .await
                                .unwrap()
                                .remove_members(&client_ids)
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

/// Benchmark to measure impact of client count in a remove commit on the runtime of commit creation and merging.
/// The group has size [GROUP_MAX].
fn commit_remove_n_clients_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Commit remove f(number clients)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        async_std::task::block_on(async {
                            let (central, id, client_ids, ..) =
                                setup_mls_and_add_clients(ciphersuite, credential.as_ref(), in_memory, GROUP_MAX).await;
                            let to_remove = client_ids[..*i].to_vec();
                            (central, id, to_remove)
                        })
                    },
                    |(central, id, client_ids)| async move {
                        let context = central.new_transaction().await.unwrap();
                        black_box(
                            context
                                .conversation_guard(&id)
                                .await
                                .unwrap()
                                .remove_members(client_ids.as_slice())
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

/// Benchmark to measure the impact of group size on the runtime of creating and merging an update commit.
fn commit_update_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Commit update f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        async_std::task::block_on(async {
                            let (central, id, ..) =
                                setup_mls_and_add_clients(ciphersuite, credential.as_ref(), in_memory, *i).await;
                            (central, id)
                        })
                    },
                    |(central, id)| async move {
                        let context = central.new_transaction().await.unwrap();
                        black_box(context.update_keying_material(&id).await.unwrap());
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

/// Benchmark to measure impact of pending add proposal count on the runtime of merging all pending proposals.
/// The group has size [GROUP_MAX].
fn commit_pending_proposals_bench_var_n_proposals(c: &mut Criterion) {
    let mut group = c.benchmark_group("Commit pending proposals f(pending size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (PENDING_RANGE).step_by(PENDING_STEP) {
            group.bench_with_input(case.benchmark_id(i, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        async_std::task::block_on(async {
                            let (central, id, ..) =
                                setup_mls_and_add_clients(ciphersuite, credential.as_ref(), in_memory, GROUP_MAX).await;

                            let context = central.new_transaction().await.unwrap();
                            for _ in 0..*i {
                                let (kp, ..) = rand_key_package(ciphersuite).await;
                                context.new_add_proposal(&id, kp).await.unwrap();
                            }
                            context.finish().await.unwrap();

                            (central, id)
                        })
                    },
                    |(central, id)| async move {
                        let context = central.new_transaction().await.unwrap();
                        black_box(context.commit_pending_proposals(&id).await.unwrap());
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

/// Benchmark to measure impact of group size on the runtime of merging all pending proposals.
/// The proposals are [PENDING_MAX] add proposals.
fn commit_pending_proposals_bench_var_group_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("Commit pending proposals f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        async_std::task::block_on(async {
                            let (central, id, ..) =
                                setup_mls_and_add_clients(ciphersuite, credential.as_ref(), in_memory, *i).await;
                            let context = central.new_transaction().await.unwrap();
                            for _ in 0..PENDING_MAX {
                                let (kp, ..) = rand_key_package(ciphersuite).await;
                                context.new_add_proposal(&id, kp).await.unwrap();
                            }
                            context.finish().await.unwrap();
                            (central, id)
                        })
                    },
                    |(central, id)| async move {
                        let context = central.new_transaction().await.unwrap();
                        black_box(context.commit_pending_proposals(&id).await.unwrap());
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
    name = commit;
    config = criterion();
    targets =
    commit_add_bench,
    commit_add_n_clients_bench, // crashes with high client counts. May be enabled when experimenting with lower numbers.
    commit_remove_bench,
    commit_remove_n_clients_bench,
    commit_update_bench,
    commit_pending_proposals_bench_var_n_proposals,
    commit_pending_proposals_bench_var_group_size,
);
criterion_main!(commit);
