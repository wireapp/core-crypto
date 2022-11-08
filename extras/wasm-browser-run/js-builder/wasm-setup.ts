import {
    WasmBindgenTestContext as Context,
    __wbgtest_console_debug,
    __wbgtest_console_log,
    __wbgtest_console_info,
    __wbgtest_console_warn,
    __wbgtest_console_error,
    default as init,
} from ""

const wrapConsoleMethod = method => {
    const eventName = `on_console_${method}`;
    const og = console[method];
    console[method] = function(...args) {
        const event = new CustomEvent(eventName, { detail: { ...args } } )
        window.dispatchEvent(event);
        og.apply(this, args);
    };
};

["debug", "log", "info", "warn", "error"].forEach(wrapConsoleMethod);

window.__wbg_test_invoke = f => f();

window.runTests = async (wasmFileLocation: string, tests: string[], args?: string[]): boolean => {
    const {
        WasmBindgenTestContext,
        __wbgtest_console_debug,
        __wbgtest_console_log,
        __wbgtest_console_info,
        __wbgtest_console_warn,
        __wbgtest_console_error,
        default: initWasm,
    } = await import(wasmFileLocation);

    const ctx = new WasmBindgenTestContext();

    if (args) {
        ctx.args(args);
    }

    // TODO: Hook window.on_console_whatever events to __wbgtest_console_whatever methods

    const wasm = await initWasm(`${wasmFileLocation}_bg.wasm`);

    const testMethods = tests.map(testName => wasm[testName]);
    const testsPassed = await ctx.run(testMethods);

    // TODO: Unhook methods

    return testsPassed;
};
