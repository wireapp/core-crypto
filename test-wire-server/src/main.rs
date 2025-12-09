#[cfg(target_family = "wasm")]
fn main() {
    panic!("Don't run this on wasm!")
}

#[cfg(not(target_family = "wasm"))]
mod non_wasm;

#[cfg(not(target_family = "wasm"))]
#[tokio::main(flavor = "current_thread")]
pub async fn main() {
    use crate::non_wasm::{bind_socket, run_server};

    let listener = bind_socket().await;
    run_server(listener).await;
}
