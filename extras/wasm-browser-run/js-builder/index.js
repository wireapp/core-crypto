import { rollup } from "rollup";
import auto from "@rollup/plugin-auto-install";
import resolve from "@rollup/plugin-node-resolve";
import typescript from '@rollup/plugin-typescript';
import html from "@rollup/plugin-html";

import { temporaryFile } from "tempy";
import fs from "node:fs/promises";

const rollupBaseOptions = {
    output: {
        file: "dist/bundle.js",
        format: 'esm',
    },
    context: "window",
    plugins: [auto(), resolve(), typescript(), html(),],
};

async function main() {
    let buildFailed = false;

    const input = ["./wasm-setup.ts"];

    // Copy Stdin into a temporary js file so that we bundle it with rollup
    const tempFile = temporaryFile({ extension: "js" });
    const tempFileHwnd = await fs.open(tempFile, "w+");
    const dest = tempFileHwnd.createWriteStream();
    process.stdin.pipe(dest);
    await tempFileHwnd.sync();

    const { size } = await tempFileHwnd.stat();
    await tempFileHwnd.close();
    if (size > 0) {
        input.push(tempFile);
    } else {
        await fs.rm(tempFile)
    }

    const rollupOptions = { input, ...rollupBaseOptions };
    let bundle;
    try {
        bundle = await rollup(rollupOptions);
    } catch(e) {
        buildFailed = true;
        console.error(e);
    }

    if (bundle) {
        await bundle.write(rollupOptions.output);
        await bundle.close();
    }

    process.exit(buildFailed ? 1 : 0);
}

main();
