import { rollup, ModuleFormat } from "rollup";
import auto from "@rollup/plugin-auto-install";
import resolve from "@rollup/plugin-node-resolve";
import typescript from '@rollup/plugin-typescript';

import { temporaryFile } from "tempy";
import fs from "node:fs";

const rollupBaseOptions = {
    output: {
        file: "dist/bundle.js",
        format: "iife" as ModuleFormat,
    },
    plugins: [auto(), resolve(), typescript()],
};

async function main() {
    let buildFailed = false;

    // Copy Stdin into a temporary js file so that we bundle it with rollup
    const tempFile = temporaryFile({ extension: "js" });
    const dest = fs.createWriteStream(tempFile);
    process.stdin.pipe(dest);

    const input = [
        "./wasm-setup.ts",
        tempFile,
    ];

    let bundle;
    try {
        bundle = await rollup({ input, ...rollupBaseOptions });
    } catch(e) {
        buildFailed = true;
        console.error(e);
    }

    if (bundle) {
        await bundle.close();
    }

    process.exit(buildFailed ? 1 : 0);
}

main();
