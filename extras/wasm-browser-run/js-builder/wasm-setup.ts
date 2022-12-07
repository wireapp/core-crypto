const wrapConsoleMethod = method => {
    const eventName = `on_console_${method}`;
    const og = console[method];
    console[method] = function(...args) {
        const event = new CustomEvent(eventName, { detail: args } );
        window.dispatchEvent(event);
        const elem = document.getElementById(`console_${method}`);
        if (elem) {
            elem.append(`${args.join("\n")}\n`);
        }
        og.apply(this, args);
    };
};

const logMethods = ["debug", "log", "info", "warn", "error"];

logMethods.forEach(wrapConsoleMethod);

(window as any).__wbg_test_invoke = f => f();

(window as any).runTests = async (wasmFileLocation: string, tests: string[], args?: string[]): Promise<boolean> => {
    const {
        WasmBindgenTestContext,
        __wbgtest_console_debug,
        __wbgtest_console_log,
        __wbgtest_console_info,
        __wbgtest_console_warn,
        __wbgtest_console_error,
        default: initWasm,
    } = await import(wasmFileLocation);

    const wasmLogMethods = {
        debug: __wbgtest_console_debug,
        log: __wbgtest_console_log,
        info: __wbgtest_console_info,
        warn: __wbgtest_console_warn,
        error: __wbgtest_console_debug,
    };

    const ctx = new WasmBindgenTestContext();

    if (args) {
        ctx.args(args);
    }

    const listeners: { [key: string]: EventListener } = logMethods.reduce((acc, method) => {
        acc[method] = (event: CustomEvent) => {
            wasmLogMethods[method].apply(wasmLogMethods[method], event.detail);
        };
        return acc;
    }, {});

    Object.entries(listeners).forEach(([method, listener]) => {
        window.addEventListener(`on_console_${method}` as unknown as keyof WindowEventMap, listener);
    });


    const wasm = await initWasm(`${wasmFileLocation}_bg.wasm`);

    const testMethods = tests.map(testName => wasm[testName]);
    const testsPassed = await ctx.run(testMethods);

    // Cleanup event listeners
    Object.entries(listeners).forEach(([method, listener]) => {
        window.removeEventListener(`on_console_${method}` as unknown as keyof WindowEventMap, listener);
    });

    // Output control div for no-WS compat
    const controlDiv = document.createElement("div");
    controlDiv.id = `control_${wasmFileLocation}`;
    document.appendChild(controlDiv);

    return testsPassed;
};
