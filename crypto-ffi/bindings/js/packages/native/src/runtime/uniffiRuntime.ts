import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const runtimeNodeNameByPlatform: Record<
    string,
    Partial<Record<string, string>>
> = {
    darwin: {
        arm64: "uniffi-runtime-napi.darwin-arm64.node",
    },
    linux: {
        x64: "uniffi-runtime-napi.linux-x64-gnu.node",
    },
};

const runtimeNodeName =
    runtimeNodeNameByPlatform[process.platform]?.[process.arch];
if (runtimeNodeName === undefined) {
    throw new Error(
        `Unsupported platform for bundled UniFFI N-API runtime: ${process.platform}/${process.arch}`
    );
}

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const runtime = require(join(here, runtimeNodeName));

export default runtime;
