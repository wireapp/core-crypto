// const wrapConsoleMethod = (method: string) => {
//     const eventName = `on_console_${method}`;
//     const og = console[method];
//     console[method] = function(...args) {
//         const event = new CustomEvent(eventName, { detail: args } );
//         window.dispatchEvent(event);
//         const str = `${args.join("\n")}\n`;
//         const levelOutput = document.getElementById(`console_${method}`);
//         if (levelOutput) {
//             levelOutput.append(str);
//         }

//         const output = document.getElementById("output");
//         if (output) {
//             output.append(str);
//         }
//         og.apply(this, args);
//     };
// };

// const logMethods = ["debug", "log", "info", "warn", "error"];

// logMethods.forEach(wrapConsoleMethod);

interface TestResultSummary {
    successful: boolean,
    success: number,
    fail: number,
    ignored: number,
    total: number,
}

type TestResultDetails = Array<[string, boolean]>;

interface SerializableTestResultContainer {
    details: TestResultDetails,
    summary: TestResultSummary,
}

class TestResultContainer {
    details: TestResultDetails = [];
    summary: TestResultSummary = {
        successful: false,
        success: 0,
        fail: 0,
        ignored: 0,
        total: 0,
    };

    #observer?: MutationObserver = null;

    /**
     * Parses a test result string from the `wasm-bindgen-test` harness and parses it into a structured dataset
     *
     * @param logStr - The raw log string
     * @returns A partial test result container, used for differential progress reports
     */
    parseTestResultString(logStr: string): TestResultContainer {
        const partialTestResult = JSON.parse(JSON.stringify(this));
        const [mainLog, summary] = logStr.split("\n\n");

        const introMatch = mainLog.match(/running (\d+) tests/);
        if (introMatch !== null) {
            const [, totalTests] = introMatch;
            this.summary.total = parseInt(totalTests, 10);
            return partialTestResult;
        }

        const mainLogMatches: Array<[string, boolean]> = [...mainLog.matchAll(/test ([\w:]+) \.{3} (\w+)/gi)].map(([, testName, testStatus]) => [testName, testStatus === "ok"]);
        this.details.push(...mainLogMatches);
        partialTestResult.details = mainLogMatches;

        if (!summary || summary.length === 0) {
            return partialTestResult;
        }

        const summaryMatches = summary.match(/test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored/);
        if (!summaryMatches) {
            return partialTestResult;
        }

        this.summary.successful = summaryMatches[1] === "ok";
        this.summary.success = parseInt(summaryMatches[2], 10);
        this.summary.fail = parseInt(summaryMatches[3], 10);
        this.summary.ignored = parseInt(summaryMatches[4], 10);
        this.summary.total = this.summary.success + this.summary.fail + this.summary.ignored;

        partialTestResult.summary = this.summary;

        return partialTestResult;
    }

    setupObserver() {
        this.disconnectObserver();

        let output = document.getElementById("output");
        if (!output) {
            output = document.createElement("pre");
            output.id = "output";
            document.body.appendChild(output);
        }

        output.textContent = "";

        this.#observer = new MutationObserver(mutationList => {
            mutationList.forEach(mutation => {
                if (mutation.type !== "childList" || mutation.target.textContent.length === 0) {
                    return;
                }

                const partial = this.parseTestResultString(mutation.target.textContent).serializable();
                console.debug(JSON.stringify({ partial }));
                mutation.target.textContent = "";
            });
        });

        this.#observer.observe(output, {
            characterData: false,
            attributes: false,
            childList: true,
            subtree: false,
        });
    }

    disconnectObserver() {
        if (this.#observer !== null) {
            this.#observer.disconnect();
            this.#observer = null;
        }
    }

    serializable(): SerializableTestResultContainer {
        return {
            details: this.details,
            summary: this.summary,
        };
    }
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

(window as any).runTests = async (fileName: string, tests: string[], testFilter?: string, args?: string[]): Promise<SerializableTestResultContainer> => {

    // let listeners: { [key: string]: EventListener };
    const testResults = new TestResultContainer();

    try {
        testResults.setupObserver();

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

        // listeners = logMethods.reduce((acc, method) => {
        //     acc[method] = (event: CustomEvent) => {
        //         wasmLogMethods[method].apply(wasmLogMethods[method], event.detail);
        //     };
        //     return acc;
        // }, {});

        // Object.entries(listeners).forEach(([method, listener]) => {
        //     window.addEventListener(`on_console_${method}` as unknown as keyof WindowEventMap, listener);
        // });

        const wasm = await initWasm(`${fileName}.wasm`);

        const ctx = new WasmBindgenTestContext();

        if (testFilter || args) {
            const passedArgs = [];
            if (args) {
                passedArgs.push(...args);
            }
            if (testFilter) {
                passedArgs.push(testFilter);
            }

            ctx.args(passedArgs);
        }

        const testMethods = tests.map(testName => wasm[testName]);
        const testsPassed = await ctx.run(testMethods);
        if (!testsPassed && testResults.summary.successful) {
            testResults.summary.successful = false;
            throw new Error("Discrepancy between test reporter and parsed test results!");
        }

        outputControlDiv(fileName);

        console.debug(JSON.stringify({ complete: testResults.serializable() }));

        return testResults;
    } catch (e) {
        outputControlDiv(fileName, e);
        throw e;
    } finally {
        // Cleanup event listeners
        // if (listeners) {
        //     Object.entries(listeners).forEach(([method, listener]) => {
        //         window.removeEventListener(`on_console_${method}` as unknown as keyof WindowEventMap, listener);
        //     });
        // }

        testResults.disconnectObserver();
    }
};
