# WASM problematic

Our code relies on SQLCipher - SQLite "fork" with encryption - which makes us rely on both SQLCipher and OpenSSL as C libraries
This implies that only the `wasm32-wasi` and `wasm32-unknown-emscripten` targets are an option.

## wasm32-wasi

That's the optimal, standards target.
But there are roadblocks to it.

* the rust-openssl library doesn't compile well to wasm32-wasi
    * This is due to `openssl-sys` and `openssl-src` not supporting `wasm32-wasi` compilation as well
    * Efforts in this direction have started: 
        * `openssl-src` v300 now supports wasm32-wasi: https://github.com/alexcrichton/openssl-src-rs/pull/119
        * Work will continue up the chain on `openssl-sys` and then `rust-openssl`
* It is still partly unknown how well SQLCipher builds to WASI given the OpenSSL blocker detailed above
    * It *should* be fine though as SQLite does compile easily to WASI

So while the background efforts to target WASI are ongoing, we need a solution for short-term support, even if ultimately targeting WASI is the goal

Pros: standards-compliant, smaller WASM bundles
Cons: Sometimes requires library compilation support when interacting with C libraries (and the `cc` crate)

## wasm32-unknown-emscripten

Compilation works fine with some tweaking but execution doesn't.
It seems the wasm imports don't work out of the box and need some JS support library.
Very hard to inspect as there's no standard behavior to expect.

Pros: Compiles, seems to work with any C-code out of the box
Cons: Bigger bundles, "black box" uninspectable behavior, execution requires some sort of support on the JS side
