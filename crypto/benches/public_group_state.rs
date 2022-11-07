use criterion::{async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize, Criterion};

use crate::utils::*;

#[path = "utils/mod.rs"]
mod utils;

fn export_pgs_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Export PublicGroupState");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup_mls(ciphersuite, &&credential, in_memory);
                        add_clients(&mut central, &id, ciphersuite, *i);
                        (central, id)
                    },
                    |(central, id)| async move {
                        black_box(central.export_public_group_state(&id).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

criterion_group!(
    name = public_group_state;
    config = criterion();
    targets = export_pgs_bench
);
criterion_main!(public_group_state);
