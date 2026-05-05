import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const libNameByPlatform: Record<string, string> = {
    darwin: "libcore_crypto_ffi.dylib",
    linux: "libcore_crypto_ffi.so",
};

const libName = libNameByPlatform[process.platform];
if (libName !== undefined && process.env["UNIFFI_LIB_PATH"] === undefined) {
    const here = dirname(fileURLToPath(import.meta.url));
    process.env["UNIFFI_LIB_PATH"] = join(here, libName);
}
