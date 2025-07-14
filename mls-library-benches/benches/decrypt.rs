use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, SamplingMode, criterion_group, criterion_main};
use mls_library_benches::{BenchSetup, BenchmarkCase as _, PlaintextGenerator, mls_rs::MlsRs, openmls::OpenMls};

fn decrypt<Setup: BenchSetup + Default>(c: &mut Criterion) {
    let mut setup = Setup::default();
    let plaintext_generator = PlaintextGenerator::default();

    let mut group = c.benchmark_group("decryption");
    group.sampling_mode(SamplingMode::Flat);

    for n_senders in [1, 10, 100, 1000] {
        for n_messages in [10_usize, 100, 1000, 10_000] {
            if n_senders > n_messages {
                continue;
            }

            let id = BenchmarkId::new(
                format!("{} decrypt(senders, messages)", Setup::ident()),
                format!("({n_senders}, {n_messages})"),
            );
            group.throughput(criterion::Throughput::Elements(n_messages as _));
            group.bench_with_input(id, &(n_senders, n_messages), |b, (n_senders, n_messages)| {
                let n_senders = *n_senders;
                let n_messages = *n_messages;

                b.iter_batched(
                    || setup.setup(&plaintext_generator, n_senders, n_messages),
                    |(case, expected_crc)| {
                        let produced_crc = black_box(case.decrypt_all());
                        debug_assert_eq!(expected_crc, produced_crc);
                    },
                    BatchSize::PerIteration,
                );
            });
        }
    }
}

criterion_group!(benches, decrypt::<OpenMls>, decrypt::<MlsRs>);
criterion_main!(benches);
