import { resolve as pathResolve } from "path";
import { fileURLToPath } from "url";

import rust from "@wasm-tool/rollup-plugin-rust";
import { generateDtsBundle } from "dts-bundle-generator";
import ts from "rollup-plugin-ts";
import typescript from "typescript";
const {
    sys: { writeFile },
} = typescript;

const __dirname = fileURLToPath(new URL(".", import.meta.url));

const paths = {
    tsconfig: pathResolve(__dirname, "./tsconfig.json"),
    ccMainEntry: pathResolve(__dirname, "./CoreCrypto.ts"),
    output: {
        js: pathResolve(
            __dirname,
            "../../../platforms/web/corecrypto.js"
        ),
        typedefs: pathResolve(__dirname, "../../../platforms/web/corecrypto.d.ts"),
    },
};

const generateDtsBundlePlugin = (entry, output) => ({
    name: "dts-bundle-generator",
    renderStart() {
        const result = generateDtsBundle(
            [
                {
                    filePath: entry,
                    output: {
                        noBanner: true,
                        exportReferencedTypes: false,
                    },
                },
            ],
            {
                preferredConfigPath: paths.tsconfig,
            }
        );
        if (!result) {
            throw new Error("Error in DTS bundle generation");
        }

        const dtsFile = result[0];
        writeFile(output, dtsFile);
    },
});

const cargoArgs = [];

if (process.env.BUILD_PROTEUS) {
    cargoArgs.push("--features", "proteus");
}

const rollup = {
    input: paths.ccMainEntry,
    output: {
        file: paths.output.js,
        format: "es",
    },
    plugins: [
        rust({
            cargoArgs,
            // wasmBindgenArgs: ["--weak-refs", "--reference-types"],
            wasmOptArgs: ["-Os"],
        }),
        ts({
            tsconfig: paths.tsconfig,
        }),
        generateDtsBundlePlugin(
            paths.ccMainEntry,
            paths.output.typedefs,
        ),
    ],
};

export default rollup;
