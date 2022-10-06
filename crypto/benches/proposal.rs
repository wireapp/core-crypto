use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion,
};

use core_crypto::{
    mls::MlsCiphersuite,
    prelude::{CertificateBundle, MlsProposal},
};

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

fn add_proposal_bench(c: &mut Criterion) {
    for (case, ciphersuite, credential) in working_test_cases() {
        let mut group = c.benchmark_group(format!("Add proposal ({})", case));
        for i in (GROUP_MIN..GROUP_MAX).step_by(GROUP_STEP) {
            group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup(&ciphersuite, &credential);
                        add_clients(&mut central, &id, &ciphersuite, *i);
                        let (kp, ..) = rand_key_package(&ciphersuite);
                        (central, id, kp)
                    },
                    |(mut central, id, kp)| async move {
                        black_box(central.new_proposal(&id, MlsProposal::Add(kp)).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

fn remove_proposal_bench(c: &mut Criterion) {
    for (case, ciphersuite, credential) in working_test_cases() {
        let mut group = c.benchmark_group(format!("Remove proposal ({})", case));
        for i in (GROUP_MIN..GROUP_MAX).step_by(GROUP_STEP) {
            group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup(&ciphersuite, &credential);
                        let client_ids = add_clients(&mut central, &id, &ciphersuite, *i);
                        (central, id, client_ids.first().unwrap().clone())
                    },
                    |(mut central, id, client_id)| async move {
                        black_box(central.new_proposal(&id, MlsProposal::Remove(client_id)).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

fn update_proposal_bench(c: &mut Criterion) {
    for (case, ciphersuite, credential) in working_test_cases() {
        let mut group = c.benchmark_group(format!("Update proposal ({})", case));
        for i in (GROUP_MIN..GROUP_MAX).step_by(GROUP_STEP) {
            group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup(&ciphersuite, &credential);
                        add_clients(&mut central, &id, &ciphersuite, *i);
                        (central, id)
                    },
                    |(mut central, id)| async move {
                        black_box(central.new_proposal(&id, MlsProposal::Update).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

criterion_group!(
    name = proposal;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = add_proposal_bench, remove_proposal_bench, update_proposal_bench
);
criterion_main!(proposal);
