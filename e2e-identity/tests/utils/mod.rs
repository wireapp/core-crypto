#![allow(dead_code)]

use rusty_jwt_tools::prelude::ClientId;

#[cfg(not(target_os = "unknown"))]
pub(crate) mod cfg;
#[cfg(not(target_os = "unknown"))]
pub(crate) mod ctx;
#[cfg(not(target_os = "unknown"))]
pub(crate) mod hooks;
#[cfg(not(target_os = "unknown"))]
pub(crate) mod idp;
#[cfg(not(target_os = "unknown"))]
pub(crate) mod stepca;

/// Container network name.
pub(crate) const NETWORK: &str = "wire";

/// Container shared memory size in bytes. By default Docker allocates 64MB.
pub(crate) const SHM: u64 = 8 * 1000 * 1000; // 8MB

pub(crate) fn rand_str(size: usize) -> String {
    use rand::distributions::{Alphanumeric, DistString};
    Alphanumeric.sample_string(&mut rand::thread_rng(), size)
}

pub(crate) fn rand_base64_str(size: usize) -> String {
    use base64::Engine as _;
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(rand_str(size))
}

pub(crate) fn rand_client_id(device_id: Option<u64>) -> ClientId {
    let device_id = device_id.unwrap_or_else(rand::random::<u64>);
    ClientId::try_from_raw_parts(
        uuid::Uuid::new_v4().as_ref(),
        device_id,
        format!("{}.com", rand_str(6)).as_bytes(),
    )
    .unwrap()
}
