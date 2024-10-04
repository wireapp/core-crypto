use criterion::{
    async_executor::AsyncStdExecutor as FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize,
    Criterion,
};

use crate::utils::*;

#[path = "utils/mod.rs"]
mod utils;

fn proposal_add_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Add proposal f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        async_std::task::block_on(async {
                            let (mut central, id) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
                            add_clients(&mut central, &id, ciphersuite, *i).await;
                            let (kp, ..) = rand_key_package(ciphersuite).await;
                            (central, id, kp)
                        })
                    },
                    |(mut central, id, kp)| async move {
                        let context = central.new_transaction().await?;
                        black_box(context.new_add_proposal(&id, kp).await.unwrap());
                        context.finish().await.unwrap();
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn proposal_remove_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Remove proposal f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        async_std::task::block_on(async {
                            let (mut central, id) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
                            let (client_ids, ..) = add_clients(&mut central, &id, ciphersuite, *i).await;
                            (central, id, client_ids.first().unwrap().clone())
                        })
                    },
                    |(mut central, id, client_id)| async move {
                        let context = central.new_transaction().await?;
                        black_box(context.new_remove_proposal(&id, client_id).await.unwrap());
                        context.finish().await.unwrap();
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn proposal_update_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Update proposal f(group size)");
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
                        let context = central.new_transaction().await?;
                        black_box(context.new_update_proposal(&id).await.unwrap());
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
    name = proposal;
    config = criterion();
    targets =
    proposal_add_bench,
    proposal_remove_bench,
    proposal_update_bench,
);
criterion_main!(proposal);
