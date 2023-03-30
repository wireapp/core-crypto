#![cfg(not(target_family = "wasm"))]

pub mod dex;
pub mod ldap;
pub mod stepca;
pub mod wiremock;

use jwt_simple::reexports::rand;

pub const NETWORK: &str = "wire";

pub(crate) fn rand_str() -> String {
    use rand::distributions::{Alphanumeric, DistString};
    Alphanumeric.sample_string(&mut rand::thread_rng(), 12)
}
