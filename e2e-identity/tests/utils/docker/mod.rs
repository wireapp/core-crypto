#![cfg(not(target_family = "wasm"))]

pub mod keycloak;
pub mod stepca;

pub const NETWORK: &str = "wire";

/// Shared Memory Size in bytes. By default docker allocates 64MB
pub const SHM: u64 = 8 * 1000 * 1000; // 8MB
