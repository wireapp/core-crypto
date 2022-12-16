#![allow(dead_code)]

#[cfg(not(target_family = "wasm"))]
pub mod display;
#[cfg(not(target_family = "wasm"))]
pub mod fake_wire_server;
#[cfg(not(target_family = "wasm"))]
pub mod helpers;
pub mod keys;
#[cfg(not(target_family = "wasm"))]
pub mod server_api;

pub fn rand_base64_str(size: usize) -> String {
    use rand::distributions::{Alphanumeric, DistString};
    let challenge: String = Alphanumeric.sample_string(&mut rand::thread_rng(), size);
    base64::encode_config(challenge, base64::URL_SAFE_NO_PAD)
}
