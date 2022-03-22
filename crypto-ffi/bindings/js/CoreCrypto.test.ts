// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

import { default as WasiContext } from "https://deno.land/std@0.122.0/wasi/snapshot_preview1.ts";
import { CoreCrypto, CoreCryptoParams } from './CoreCrypto.ts';

const wasiCtx = new WasiContext({
    args: Deno.args,
    env: Deno.env.toObject(),
});

const asm2wasmImports = {
    "f64-rem": function (x: number, y: number) {
        return x % y
    },
    "debugger": function () {}
};

CoreCrypto.init = async function init(wasmFile: string, params: CoreCryptoParams): Promise<CoreCrypto> {
    const wasmCode = await Deno.readFile(wasmFile);
    const module = new WebAssembly.Module(wasmCode);
    const instance = new WebAssembly.Instance(module, {
        "env": {
            __memory_base: 0,
            __table_base: 0,
            memory: new WebAssembly.Memory({ initial: 1 }),
            STACKTOP: 0,
        },
        "global": {
            "NaN": NaN,
            Infinity: Infinity,
        },
        "global.Math": Math as any,
        "wasi_snapshot_preview1": wasiCtx.exports,
    });

    return new CoreCrypto({ wasmModule: { module, instance }, ...params });
}.bind(CoreCrypto);

const coreCrypto = await CoreCrypto.init("./target/wasm32-unknown-emscripten/debug/core_crypto_ffi.wasm", {
    path: "./test.edb",
    key: "test",
    clientId: "deno-test",
});

console.log(`CoreCrypto v${coreCrypto.version()} [OK]`);
