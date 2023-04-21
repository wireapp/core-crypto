use criterion::{async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize, Criterion};
use futures_lite::future::block_on;

use crate::utils::*;

#[path = "utils/mod.rs"]
mod utils;

fn generate_key_package_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Generate KeyPackage f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || setup_mls(ciphersuite, &credential, in_memory),
                    |(central, _)| async move {
                        black_box(central.get_or_create_client_keypackages(ciphersuite, *i).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn count_key_packages_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Count KeyPackage");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (central, ..) = setup_mls(ciphersuite, &credential, in_memory);
                        block_on(async {
                            central.get_or_create_client_keypackages(ciphersuite, *i).await.unwrap();
                        });
                        central
                    },
                    |central| async move {
                        black_box(central.client_valid_key_packages_count(ciphersuite).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

criterion_group!(
    name = key_package;
    config = criterion();
    targets =
    generate_key_package_bench,
    count_key_packages_bench,
);
criterion_main!(key_package);
