const path = require("path");
const abs = path.resolve("../../node_modules/@wireapp/core-crypto/platforms/web/assets/core_crypto_ffi-32b81580.wasm")

config.files.push({
    pattern: abs,
    served: true,
    watched: false,
    included: false,
    nocache: false,
});

config.proxies["/assets/core_crypto_ffi-32b81580.wasm"] = `/absolute${abs}`
