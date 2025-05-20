use std::hint::black_box;

use core_crypto::prelude::MlsCredentialType;
use criterion::{
    BatchSize, Criterion, async_executor::AsyncStdExecutor as FuturesExecutor, criterion_group, criterion_main,
};

use crate::utils::*;

#[path = "utils/mod.rs"]
mod utils;

fn generate_key_package_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Generate KeyPackage f(group size)");
    for (case, ciphersuite, credential, in_memory) in MlsTestCase::values() {
        let credential_type = credential
            .as_ref()
            .map(|_| MlsCredentialType::X509)
            .unwrap_or(MlsCredentialType::Basic);
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || async_std::task::block_on(setup_mls(ciphersuite, credential.as_ref(), in_memory)),
                    |(central, _, _)| async move {
                        let context = central.new_transaction().await.unwrap();
                        black_box(
                            context
                                .get_or_create_client_keypackages(ciphersuite, credential_type, *i)
                                .await
                                .unwrap(),
                        );
                        context.finish().await.unwrap();
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
        let credential_type = credential
            .as_ref()
            .map(|_| MlsCredentialType::X509)
            .unwrap_or(MlsCredentialType::Basic);
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        async_std::task::block_on(async {
                            let (central, ..) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;

                            let context = central.new_transaction().await.unwrap();
                            context
                                .get_or_create_client_keypackages(ciphersuite, credential_type, *i)
                                .await
                                .unwrap();
                            context.finish().await.unwrap();
                            central
                        })
                    },
                    |central| async move {
                        let context = central.new_transaction().await.unwrap();
                        black_box(
                            context
                                .client_valid_key_packages_count(ciphersuite, credential_type)
                                .await
                                .unwrap(),
                        );
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
    name = key_package;
    config = criterion();
    targets =
    generate_key_package_bench,
    count_key_packages_bench,
);
criterion_main!(key_package);
