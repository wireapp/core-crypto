import rust from "@wasm-tool/rollup-plugin-rust";
import { generateDtsBundle } from "dts-bundle-generator";
import { resolve as pathResolve } from "path";
import ts from "rollup-plugin-ts";
import typescript from "typescript";
const {
    sys: { writeFile },
} = typescript;

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
                preferredConfigPath: pathResolve(__dirname, "./tsconfig.json"),
            }
        );
        if (!result) {
            throw new Error("Error in DTS bundle generation");
        }

        const dtsFile = result[0];
        writeFile(output, dtsFile);
    },
});

const getOutput = (format = "es2017") => {
    return {
        file: pathResolve(
            __dirname,
            "../../../platforms/web/" + format + "/corecrypto.js"
        ),
        format: "es",
    };
};

const getPlugins = (format = "es2017") => {
    return [
        rust(),
        ts({
            tsconfig: {
                fileName: pathResolve(__dirname, "./tsconfig.json"),
                hook: (resolvedConfig) => ({
                    ...resolvedConfig,
                    target: format,
                }),
            },
        }),
        generateDtsBundlePlugin(
            pathResolve(__dirname, "./CoreCrypto.ts"),
            pathResolve(
                __dirname,
                "../../../platforms/web/" + format + "/corecrypto.d.ts"
            )
        ),
    ];
};

const rollup = (_args) => {
    const input = pathResolve(__dirname, "./CoreCrypto.ts");

    return [
        {
            input,
            output: getOutput("es2017"),
            plugins: getPlugins("es2017"),
        },
        {
            input,
            output: getOutput("es2019"),
            plugins: getPlugins("es2019"),
        },
    ];
};

export default rollup;
