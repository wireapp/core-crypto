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

await cp(`${baseDir}/wasm/core-crypto-ffi_bg.wasm`, `${destDir}/core-crypto-ffi_bg.wasm`);
await rename(`${destDir}/CoreCrypto.js`, `${destDir}/corecrypto.js`);
await rename(`${destDir}/CoreCrypto.d.ts`, `${destDir}/corecrypto.d.ts`);

