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
const native = require(join(here, runtimeNodeName));

export default {
    ...native,
    FfiType: {
        UInt8: { tag: "UInt8" },
        Int8: { tag: "Int8" },
        UInt16: { tag: "UInt16" },
        Int16: { tag: "Int16" },
        UInt32: { tag: "UInt32" },
        Int32: { tag: "Int32" },
        UInt64: { tag: "UInt64" },
        Int64: { tag: "Int64" },
        Float32: { tag: "Float32" },
        Float64: { tag: "Float64" },
        Handle: { tag: "Handle" },
        RustBuffer: { tag: "RustBuffer" },
        ForeignBytes: { tag: "ForeignBytes" },
        RustCallStatus: { tag: "RustCallStatus" },
        VoidPointer: { tag: "VoidPointer" },
        Void: { tag: "Void" },
        Callback: (name: string) => ({ tag: "Callback", name }),
        Struct: (name: string) => ({ tag: "Struct", name }),
        Reference: (inner: unknown) => ({ tag: "Reference", inner }),
        MutReference: (inner: unknown) => ({ tag: "MutReference", inner }),
    },
};
