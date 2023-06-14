use async_std::task::block_on;
use criterion::{async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize, Criterion};

use core_crypto::prelude::MlsProposal;

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
                        let (mut central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        add_clients(&mut central, &id, ciphersuite, *i);
                        let (kp, ..) = block_on(async { rand_key_package(ciphersuite).await });
                        (central, id, kp)
                    },
                    |(mut central, id, kp)| async move {
                        black_box(central.new_proposal(&id, MlsProposal::Add(kp)).await.unwrap());
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
                        let (mut central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        let (client_ids, ..) = add_clients(&mut central, &id, ciphersuite, *i);
                        (central, id, client_ids.first().unwrap().clone())
                    },
                    |(mut central, id, client_id)| async move {
                        black_box(central.new_proposal(&id, MlsProposal::Remove(client_id)).await.unwrap());
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
                        let (mut central, id) = setup_mls(ciphersuite, &credential, in_memory);
                        add_clients(&mut central, &id, ciphersuite, *i);
                        (central, id)
                    },
                    |(mut central, id)| async move {
                        black_box(central.new_proposal(&id, MlsProposal::Update).await.unwrap());
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
