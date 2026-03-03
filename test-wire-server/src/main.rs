#[cfg(target_family = "wasm")]
fn main() {
    panic!("Don't run this on wasm!")
}

#[cfg(not(target_family = "wasm"))]
mod non_wasm;

#[cfg(not(target_family = "wasm"))]
fn main() {
    use crate::non_wasm::{bind_socket, run_server};
    // smol single-threaded executor
    smol::block_on(async {
        // bind to a local socket
        let listener = bind_socket().await;

        // run the test Wire server
        run_server(listener).await;
    });
}
