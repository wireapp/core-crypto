use criterion::{
    async_executor::FuturesExecutor, black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion,
};
use futures_lite::future::block_on;
use rand::distributions::{Alphanumeric, DistString};

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

const MSG_MAX: usize = 10_010;
const MSG_MIN: usize = 10;
const MSG_STEP: usize = 2000;

fn encryption_bench_var_group_size(c: &mut Criterion) {
    for (case, ciphersuite, credential) in working_test_cases() {
        let mut group = c.benchmark_group(format!("Encrypt var(group size) ({})", case));
        for i in (GROUP_MIN..GROUP_MAX).step_by(GROUP_STEP) {
            group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup(&ciphersuite, &credential);
                        add_clients(&mut central, &id, &ciphersuite, *i);
                        let text = Alphanumeric.sample_string(&mut rand::thread_rng(), MSG_MAX);
                        (central, id, text)
                    },
                    |(mut central, id, text)| async move {
                        black_box(central.encrypt_message(&id, text).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

fn encryption_bench_var_msg_size(c: &mut Criterion) {
    for (case, ciphersuite, credential) in working_test_cases() {
        let mut group = c.benchmark_group(format!("Encrypt var(msg size) ({})", case));
        for i in (MSG_MIN..MSG_MAX).step_by(MSG_STEP) {
            group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut central, id) = setup(&ciphersuite, &credential);
                        add_clients(&mut central, &id, &ciphersuite, GROUP_MAX);
                        let text = Alphanumeric.sample_string(&mut rand::thread_rng(), *i);
                        (central, id, text)
                    },
                    |(mut central, id, text)| async move {
                        black_box(central.encrypt_message(&id, text).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

fn decryption_bench(c: &mut Criterion) {
    for (case, ciphersuite, credential) in working_test_cases() {
        let mut group = c.benchmark_group(format!("Decrypt ({})", case));
        for i in (MSG_MIN..MSG_MAX).step_by(MSG_STEP) {
            group.bench_with_input(BenchmarkId::from_parameter(i), &i, |b, i| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        let (mut alice_central, id) = setup(&ciphersuite, &credential);
                        let (mut bob_central, ..) = new_central(&credential);
                        invite(&mut alice_central, &mut bob_central, &id, &ciphersuite);

                        let text = Alphanumeric.sample_string(&mut rand::thread_rng(), *i);
                        let encrypted = block_on(async { alice_central.encrypt_message(&id, text).await.unwrap() });
                        (bob_central, id, encrypted)
                    },
                    |(mut central, id, encrypted)| async move {
                        black_box(central.decrypt_message(&id, encrypted).await.unwrap());
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

criterion_group!(
    name = encryption;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = encryption_bench_var_group_size, encryption_bench_var_msg_size, decryption_bench
);
criterion_main!(encryption);
