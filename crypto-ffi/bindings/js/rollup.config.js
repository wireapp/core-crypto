import rust from "@wasm-tool/rollup-plugin-rust";
import { generateDtsBundle } from "dts-bundle-generator";
import { resolve as pathResolve } from "path";
import ts from "rollup-plugin-ts";
import typescript from "typescript";
const { sys: { writeFile } } = typescript;

const generateDtsBundlePlugin = (entry, output) => ({
  name: "dts-bundle-generator",
  renderStart() {
    const result = generateDtsBundle(
      [
        {
          filePath: entry,
          output: {
            noBanner: true,
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

const config = {
  input: pathResolve(__dirname, "./CoreCrypto.ts"),
  output: {
    file: pathResolve(__dirname, "../../../platforms/web/corecrypto.js"),
    format: "es",
  },
  plugins: [
    rust(),
    ts({
      tsconfig: pathResolve(__dirname, "./tsconfig.json"),
    }),
    generateDtsBundlePlugin(
      pathResolve(__dirname, "./CoreCrypto.ts"),
      pathResolve(__dirname, "../../../platforms/web/corecrypto.d.ts")
    ),
  ],
};

export default config;
