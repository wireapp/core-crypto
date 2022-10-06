use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion,
};

use core_crypto::{mls::MlsCiphersuite, prelude::CertificateBundle};

use crate::utils::*;

#[path = "utils.rs"]
mod utils;

// FIXME: currently operations do not work for other ciphersuites
fn working_test_cases() -> impl Iterator<Item = (MlsTestCase, MlsCiphersuite, Option<CertificateBundle>)> {
    MlsTestCase::values().filter(|(c, ..)| match c {
        MlsTestCase::Basic_Ciphersuite1 => true,
        _ => false,
    })
}

fn export_pgs_bench(c: &mut Criterion) {
    for (case, ciphersuite, credential) in working_test_cases() {
        let mut group = c.benchmark_group(format!("PublicGroupState ({})", case));
        for i in (GROUP_MIN..GROUP_MAX).step_by(GROUP_STEP) {
            group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup(&ciphersuite, &&credential);
                        add_clients(&mut central, &id, &ciphersuite, *i);
                        (central, id)
                    },
                    |(central, id)| async move {
                        black_box(central.export_public_group_state(&id).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

criterion_group!(
    name = public_group_state;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = export_pgs_bench
);
criterion_main!(public_group_state);
