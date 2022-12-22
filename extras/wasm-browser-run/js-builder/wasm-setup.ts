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

interface TestResultContainer {
    details: Array<[string, boolean]>,
    summary: {
        successful: boolean,
        success: number,
        fail: number,
        ignored: number,
        total: number,
    },
}

let testResults: TestResultContainer = {
    details: [],
    summary: {
        successful: false,
        success: 0,
        fail: 0,
        ignored: 0,
        total: 0,
    },
};

const parseTestResultString = (logStr: string) => {
    const [mainLog, summary] = logStr.split("\n\n");

    const introMatch = mainLog.match(/running (\d+) tests/);
    if (introMatch !== null) {
        const [, totalTests] = introMatch;
        testResults.summary.total = parseInt(totalTests, 10);
        return;
    }

    const mainLogMatches: Array<[string, boolean]> = [...mainLog.matchAll(/test ([\w:]+) \.{3} (\w+)/gi)].map(([, testName, testStatus]) => [testName, testStatus === "ok"]);
    testResults.details.push(...mainLogMatches);

    if (!summary || summary.length === 0) {
        return;
    }

    const summaryMatches = summary.match(/test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored/);
    if (!summaryMatches) {
        return;
    }

    testResults.summary.successful = summaryMatches[1] === "ok";
    testResults.summary.success = parseInt(summaryMatches[2], 10);
    testResults.summary.fail = parseInt(summaryMatches[3], 10);
    testResults.summary.ignored = parseInt(summaryMatches[4], 10);
};

const setupOutputObserver = () => {
    testResults = {
        details: [],
        summary: {
            successful: false,
            success: 0,
            fail: 0,
            ignored: 0,
            total: 0,
        },
    };
    let output = document.getElementById("output");
    if (!output) {
        output = document.createElement("pre");
        output.id = "output";
        document.body.appendChild(output);
    }

    output.textContent = "";

    const observer = new MutationObserver(mutationList => {
        mutationList.forEach(mutation => {
            if (mutation.type !== "childList" || output.textContent.length === 0) {
                return;
            }

            parseTestResultString(output.textContent);
            // console.info(output.textContent);
            output.textContent = "";
        });
    });

    observer.observe(output, {
        characterData: false,
        attributes: false,
        childList: true,
        subtree: false,
    });

    return observer;
}

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

(window as any).runTests = async (fileName: string, tests: string[], args?: string[]): Promise<TestResultContainer> => {

    let listeners: { [key: string]: EventListener };
    let observer: MutationObserver;

    try {
        observer = setupOutputObserver();

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
        if (!testsPassed && testResults.summary.successful) {
            testResults.summary.successful = false;
            throw new Error("Discrepancy between test reporter and parsed test results!");
        }

        outputControlDiv(fileName);

        return testResults;
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

        if (observer) {
            observer.disconnect();
        }
    }
};
