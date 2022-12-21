const wrapConsoleMethod = (method: string) => {
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

const outputControlDiv = (fileName: string, error?: Error): void => {
    const id = `control_${fileName}`;
    if (document.getElementById(id) !== null) {
        return;
    }

    // Output control div for no-WS compat
    const controlDiv = document.createElement("pre");
    controlDiv.id = id;
    if (error) {
        controlDiv.textContent = `\t${error.toString()}\n\n\tStacktrace: ${error.stack.toString()}`;
    }
    document.body.appendChild(controlDiv);
};

(window as any).__wbg_test_invoke = f => f();

(window as any).runTests = async (fileName: string, tests: string[], args?: string[]): Promise<boolean> => {

    let listeners: { [key: string]: EventListener };

    try {
        const {
            WasmBindgenTestContext,
            __wbgtest_console_debug,
            __wbgtest_console_log,
            __wbgtest_console_info,
            __wbgtest_console_warn,
            __wbgtest_console_error,
            default: initWasm,
        } = await import(`./${fileName}.js`);

        const wasmLogMethods = {
            debug: __wbgtest_console_debug,
            log: __wbgtest_console_log,
            info: __wbgtest_console_info,
            warn: __wbgtest_console_warn,
            error: __wbgtest_console_debug,
        };

        listeners = logMethods.reduce((acc, method) => {
            acc[method] = (event: CustomEvent) => {
                wasmLogMethods[method].apply(wasmLogMethods[method], event.detail);
            };
            return acc;
        }, {});

        Object.entries(listeners).forEach(([method, listener]) => {
            window.addEventListener(`on_console_${method}` as unknown as keyof WindowEventMap, listener);
        });

        const wasm = await initWasm(`${fileName}.wasm`);

        const ctx = new WasmBindgenTestContext();

        if (args) {
            ctx.args(args);
        }

        const testMethods = tests.map(testName => wasm[testName]);
        const testsPassed = await ctx.run(testMethods);

        outputControlDiv(fileName);

        return testsPassed;
    } catch (e) {
        outputControlDiv(fileName, e);
        throw e;
    } finally {
        // Cleanup event listeners
        if (listeners) {
            Object.entries(listeners).forEach(([method, listener]) => {
                window.removeEventListener(`on_console_${method}` as unknown as keyof WindowEventMap, listener);
            });
        }
    }
};
