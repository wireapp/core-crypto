use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion,
};
use futures_lite::future::block_on;

use crate::utils::*;

#[path = "utils.rs"]
mod utils;

fn generate_key_packages(c: &mut Criterion) {
    for (case, ciphersuite, credential) in MlsTestCase::values() {
        let mut group = c.benchmark_group(format!("Generate Key Package ({})", case));
        for i in (GROUP_MIN..GROUP_MAX).step_by(GROUP_STEP) {
            group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || setup(&ciphersuite, &credential),
                    |(central, _)| async move {
                        black_box(central.client_keypackages(*i).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

fn count_key_packages(c: &mut Criterion) {
    for (case, ciphersuite, credential) in MlsTestCase::values() {
        let mut group = c.benchmark_group(format!("Count Key Package ({})", case));
        for i in (GROUP_MIN..GROUP_MAX).step_by(GROUP_STEP) {
            group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (central, ..) = setup(&ciphersuite, &credential);
                        block_on(async {
                            central.client_keypackages(*i).await.unwrap();
                        });
                        central
                    },
                    |central| async move {
                        black_box(central.client_valid_keypackages_count().await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

criterion_group!(
    name = key_package;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = generate_key_packages, count_key_packages
);
criterion_main!(key_package);
