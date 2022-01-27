import { default as WasiContext } from "https://deno.land/std@0.122.0/wasi/snapshot_preview1.ts";
import { CoreCrypto, CoreCryptoParams } from './CoreCrypto.ts';

const wasiCtx = new WasiContext({
    args: Deno.args,
    env: Deno.env.toObject(),
})

CoreCrypto.init = async function init(wasmFile: string, params: CoreCryptoParams): Promise<CoreCrypto> {
    const wasmCode = await Deno.readFile(wasmFile);
    const module = new WebAssembly.Module(wasmCode);
    const instance = new WebAssembly.Instance(module, {
        env: {
            __memory_base: 0,
            __table_base: 0,
            memory: new WebAssembly.Memory({ initial: 1 }),
        },
        wasi_snapshot_preview1: wasiCtx.exports,
    });
    const self = new CoreCrypto({ wasmModule: { module, instance }, ...params });
    return self;
}.bind(CoreCrypto);

const coreCrypto = await CoreCrypto.init("./target/wasm32-unknown-emscripten/debug/core_crypto_ffi.wasm", {
    path: "./test.edb",
    key: "test",
    clientId: "deno-test",
});
