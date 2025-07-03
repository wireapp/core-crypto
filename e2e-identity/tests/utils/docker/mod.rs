#![cfg(not(target_family = "wasm"))]

pub mod keycloak;
pub mod stepca;
pub mod wiremock;

use jwt_simple::reexports::rand;

pub const NETWORK: &str = "wire";

/// Shared Memory Size in bytes. By default docker allocates 64MB
pub const SHM: u64 = 8 * 1000 * 1000; // 8MB

pub(crate) fn rand_str() -> String {
    use rand::distributions::{Alphanumeric, DistString};
    Alphanumeric.sample_string(&mut rand::thread_rng(), 12)
}
