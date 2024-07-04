use criterion::{
    async_executor::AsyncStdExecutor as FuturesExecutor,  criterion_group, criterion_main,
    Criterion,
};
use openmls_traits::types::Ciphersuite;

use crate::utils::*;

#[path = "utils/mod.rs"]
mod utils;

fn join_large_group_bench(c: &mut Criterion) {
    const CLIENT_COUNT: usize = 2000;
    c.bench_function(format!("join_large_group_{CLIENT_COUNT}_{CLIENT_COUNT}_clients").as_str(), |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            let (ciphersuite, credential, in_memory) = (Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256.into(), None, true);
            let (mut alice_central, id) = setup_mls(ciphersuite, credential.as_ref(), in_memory).await;
            add_clients(&mut alice_central, &id, ciphersuite, CLIENT_COUNT).await;
        });
    });
}

criterion_group!(
    name = create_group;
    config = criterion();
    targets =
    join_large_group_bench
);
criterion_main!(create_group);
