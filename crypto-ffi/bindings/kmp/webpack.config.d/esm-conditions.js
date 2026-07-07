// Allow webpack to resolve ESM-only exports (e.g. @wireapp/core-crypto/browser).
// The package uses "import" condition only; without this, webpack falls back to
// "require" and fails to find the subpath export.
config.resolve = config.resolve || {};
config.resolve.conditionNames = ["import", "module", "webpack", "development", "browser"];

// The browser bundle of @wireapp/core-crypto references some Node.js built-ins
// (fs/promises) even when running in a browser context. Tell webpack to ignore them.
config.resolve.fallback = Object.assign(config.resolve.fallback || {}, {
    "fs": false,
    "fs/promises": false,
    "path": false,
    "os": false,
    "crypto": false,
});

// // Enable async WebAssembly support — required by the @wireapp/core-crypto WASM binary.
// config.experiments = Object.assign(config.experiments || {}, {
//     asyncWebAssembly: true,
// });

// Expose the WASM binary as an asset/resource so it can be fetched by URL at runtime.
// This makes @wireapp/core-crypto's initWasmModule() able to resolve the file.
// config.module = config.module || {};
// config.module.rules = (config.module.rules || []).concat([{
//     test: /index_bg\.wasm$/,
//     type: 'asset/resource',
// }]);
