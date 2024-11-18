import dts from 'bun-plugin-dts'
import { unlink, rename } from "node:fs/promises";

const baseDir = "./bindings/js";
const destDir = "../platforms/web";

const cp = async (from: string, to: string, move: boolean = false) => {
    const input = Bun.file(from);
    await Bun.write(to, input);
    if (move) {
        await unlink(from);
    }
}

// @ts-expect-error S1378: Top-level await expressions are only allowed when the module option is set to es2022, esnext, system, node16, nodenext, or preserve, and the target option is set to es2017 or higher.
await Bun.build({
    entrypoints: [`${baseDir}/CoreCrypto.ts`],
    outdir: destDir,
    target: "browser",
    plugins: [
        dts({
            output: {
                noBanner: true,
                exportReferencedTypes: false,
                respectPreserveConstEnum: true,
            },
            compilationOptions: {
                preferredConfigPath: `${baseDir}/tsconfig.json`,
            }
        })
    ],
});

// @ts-expect-error S1378: Top-level await expressions are only allowed when the module option is set to es2022, esnext, system, node16, nodenext, or preserve, and the target option is set to es2017 or higher.
await cp(`${baseDir}/wasm/core-crypto-ffi_bg.wasm`, `${destDir}/core-crypto-ffi_bg.wasm`);
// @ts-expect-error S1378: Top-level await expressions are only allowed when the module option is set to es2022, esnext, system, node16, nodenext, or preserve, and the target option is set to es2017 or higher.
await rename(`${destDir}/CoreCrypto.js`, `${destDir}/corecrypto.js`);
// @ts-expect-error S1378: Top-level await expressions are only allowed when the module option is set to es2022, esnext, system, node16, nodenext, or preserve, and the target option is set to es2017 or higher.
await rename(`${destDir}/CoreCrypto.d.ts`, `${destDir}/corecrypto.d.ts`);

