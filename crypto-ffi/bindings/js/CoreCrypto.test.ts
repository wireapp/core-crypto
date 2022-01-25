import { CoreCrypto, CoreCryptoParams } from './CoreCrypto.ts';

CoreCrypto.init = async function init(wasmFile: string, params: CoreCryptoParams): Promise<CoreCrypto> {
    const wasmCode = await Deno.readFile(wasmFile);
    const module = new WebAssembly.Module(wasmCode);
    const instance = new WebAssembly.Instance(module, {});
    const self = new CoreCrypto({ wasmModule: { module, instance }, ...params });
    return self;
}.bind(CoreCrypto);

const coreCrypto = await CoreCrypto.init("./target/wasm32-unknown-emscripten/debug/core_crypto_ffi.wasm", {
    path: "./test.edb",
    key: "test",
    clientId: "deno-test",
});
