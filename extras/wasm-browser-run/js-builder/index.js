import { rollup } from "rollup";
import auto from "@rollup/plugin-auto-install";
import resolve from "@rollup/plugin-node-resolve";
import typescript from '@rollup/plugin-typescript';
import html from "@rollup/plugin-html";

import { temporaryFile } from "tempy";
import fs from "node:fs/promises";

const template = ({ attributes, files, meta, publicPath, title }) => {
    const makeHtmlAttributes = (attributes) => {
        if (!attributes) {
            return "";
        }

        const keys = Object.keys(attributes);
        // eslint-disable-next-line no-param-reassign
        return keys.reduce((result, key) => (result += ` ${key}="${attributes[key]}"`), '');
    };

    const scripts = (files.js ?? [])
    .map(({ fileName }) => {
      const attrs = makeHtmlAttributes(attributes.script);
      return `<script src="${publicPath}${fileName}"${attrs}></script>`;
    })
    .join('\n');

  const links = (files.css ?? [])
    .map(({ fileName }) => {
      const attrs = makeHtmlAttributes(attributes.link);
      return `<link href="${publicPath}${fileName}" rel="stylesheet"${attrs}>`;
    })
    .join('\n');

  const metas = meta
    .map((input) => {
      const attrs = makeHtmlAttributes(input);
      return `<meta${attrs}>`;
    })
    .join('\n');

    return `\
<!DOCTYPE html>
<html${makeHtmlAttributes(attributes.html)}>
  <head>
    ${metas}
    <title>${title}</title>
    ${links}
  </head>
  <body>
    <pre id="output"></pre>
    <pre id="console_debug"></pre>
    <pre id="console_log"></pre>
    <pre id="console_info"></pre>
    <pre id="console_warn"></pre>
    <pre id="console_error"></pre>
    ${scripts}
  </body>
</html>`;
};

const rollupBaseOptions = {
    output: {
        file: "dist/bundle.js",
        format: 'esm',
    },
    context: "window",
    plugins: [
        auto(),
        resolve(),
        typescript({
            noEmitOnError: true,
            compilerOptions: {
                target: "es2020",
            },
        }),
        html(),
    ],
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

    const { size } = await fs.stat(tempFile);
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

    console.log("Build finished!");

    process.exit(buildFailed ? 1 : 0);
}

main();
