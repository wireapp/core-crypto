use std::hint::black_box;

use core_crypto::Credential;
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
                        let (client, ..) =
                            smol::block_on(setup_mls(ciphersuite, certificate_bundle.as_ref(), in_memory, true));
                        let client_id = smol::block_on(client.id()).unwrap();
                        let credential = match certificate_bundle.clone() {
                            Some(certificate_bundle) => Credential::x509(ciphersuite, certificate_bundle).unwrap(),
                            None => Credential::basic(ciphersuite, client_id, client.openmls_crypto()).unwrap(),
                        };
                        (client, credential)
                    },
                    |(central, credential)| async move {
                        let context = central.new_transaction().await.unwrap();
                        let credential_ref = context.add_credential(credential).await.unwrap();

                        black_box(for _ in 0..*i {
                            let _kp = context.generate_keypackage(&credential_ref, None).await.unwrap();
                        });
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
                            let (client, ..) =
                                setup_mls(ciphersuite, certificate_bundle.as_ref(), in_memory, true).await;
                            let client_id = client.id().await.unwrap();
                            let credential = match certificate_bundle.clone() {
                                Some(certificate_bundle) => Credential::x509(ciphersuite, certificate_bundle).unwrap(),
                                None => Credential::basic(ciphersuite, client_id, client.openmls_crypto()).unwrap(),
                            };

                            let context = client.new_transaction().await.unwrap();
                            let credential_ref = context.add_credential(credential).await.unwrap();

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
