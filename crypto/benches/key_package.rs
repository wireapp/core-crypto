use std::hint::black_box;

use criterion::{
    BatchSize, Criterion, async_executor::SmolExecutor as FuturesExecutor, criterion_group, criterion_main,
};

use crate::utils::*;

#[path = "utils/mod.rs"]
mod utils;

fn generate_key_package_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Generate KeyPackage f(group size)");
    for (case, ciphersuite, certificate_bundle, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        smol::block_on(async {
                            let (client, _, _, credential_ref) =
                                setup_mls(ciphersuite, certificate_bundle.as_ref(), in_memory, true).await;

                            let tx_context = client.new_transaction().await.unwrap();
                            (
                                tx_context,
                                credential_ref.expect("we definitely created a credential in setup_mls"),
                            )
                        })
                    },
                    |(context, credential_ref)| async move {
                        for _ in 0..*i {
                            let _kp = black_box(context.generate_keypackage(&credential_ref, None).await.unwrap());
                        }
                        context.finish().await.unwrap();
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn get_key_packages_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Count KeyPackage");
    for (case, ciphersuite, certificate_bundle, in_memory) in MlsTestCase::values() {
        for i in (GROUP_RANGE).step_by(GROUP_STEP) {
            group.bench_with_input(case.benchmark_id(i + 1, in_memory), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        smol::block_on(async {
                            let (client, _, _, credential_ref) =
                                setup_mls(ciphersuite, certificate_bundle.as_ref(), in_memory, true).await;
                            let credential_ref = credential_ref.expect("we did add a credential above");
                            let context = client.new_transaction().await.unwrap();

                            for _ in 0..*i {
                                let _kp = context.generate_keypackage(&credential_ref, None).await.unwrap();
                            }

                            context.finish().await.unwrap();
                            client
                        })
                    },
                    |central| async move {
                        let context = central.new_transaction().await.unwrap();
                        black_box(context.get_keypackage_refs().await.unwrap());
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
    get_key_packages_bench,
);
criterion_main!(key_package);
