#![allow(dead_code)]

use base64::Engine;

#[cfg(not(target_family = "wasm"))]
pub mod display;
#[cfg(not(target_family = "wasm"))]
pub mod fake_wire_server;
#[cfg(not(target_family = "wasm"))]
pub mod helpers;
pub mod keys;
#[cfg(not(target_family = "wasm"))]
pub mod server_api;

pub mod oidc;

pub fn rand_base64_str(size: usize) -> String {
    use rand::distributions::{Alphanumeric, DistString};
    let challenge: String = Alphanumeric.sample_string(&mut rand::thread_rng(), size);
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(challenge)
}
