const wrapConsoleMethod = (method: string) => {
    const eventName = `on_console_${method}`;
    const og = console[method];
    console[method] = function(...args) {
        const event = new CustomEvent(eventName, { detail: args } );
        window.dispatchEvent(event);
        const str = `${args.join("\n")}\n`;
        const levelOutput = document.getElementById(`console_${method}`);
        if (levelOutput) {
            levelOutput.append(str);
        }
        og.apply(this, args);
    };
};

const logMethods = ["debug", "log", "info", "warn", "error"];
logMethods.forEach(wrapConsoleMethod);

const wasmBindgenDivs = ["output", ...logMethods.map(m => `console_${m}`)];
wasmBindgenDivs.forEach(id => ensureDiv(id));

interface TestResultSummary {
    successful: boolean;
    success: number;
    fail: number;
    ignored: number;
    total: number;
}

interface TestResultDetails {
    [testName: string]: boolean;
};

interface SerializableTestResultContainer {
    details: TestResultDetails;
    summary: TestResultSummary;
}

class TestResultContainer implements SerializableTestResultContainer {
    details: TestResultDetails = {};
    summary: TestResultSummary = {
        successful: false,
        success: 0,
        fail: 0,
        ignored: 0,
        total: 0,
    };

    private rawLog: string = "";
    private observer?: MutationObserver = null;

    getRawLog(): string {
        return this.rawLog;
    }

    /**
     * Parses a test result string from the `wasm-bindgen-test` harness and parses it into a structured dataset
     *
     * @param logStr - The raw log string
     * @returns A partial test result container, used for differential progress reports
     */
    parseTestResultString(logStr: string): TestResultContainer {
        const partialTestResult = JSON.parse(JSON.stringify(this));

        const introMatch = logStr.match(/running (\d+) tests/);
        if (introMatch !== null) {
            const [, totalTests] = introMatch;
            this.summary.total = parseInt(totalTests, 10);
        }

        const testRegexp = /test ([\w:]+) \.{3} (\w+)/gi;
        let match;
        const mainLogMatches: TestResultDetails = {};
        while ((match = testRegexp.exec(logStr)) !== null) {
            const [, testName, testStatus] = match;
            mainLogMatches[testName] = testStatus === "ok";
        }

        if (Object.keys(mainLogMatches).length > 0) {
            this.details = Object.assign(this.details, mainLogMatches);
            partialTestResult.details = mainLogMatches;
        }

        const summaryMatches = logStr.match(/test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored/);
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

    setupObserver(noCapture: boolean): MutationObserver {
        this.disconnectObserver();
        let prevPartialOutput;

        this.observer = new MutationObserver(mutationList => {
            for (const mutation of mutationList) {
                if (mutation.type !== "childList") {
                    continue;
                }

                const currentLog = mutation.target.textContent;
                if (currentLog.length === 0) {
                    continue;
                }

                this.rawLog += currentLog;
                const partial = this.parseTestResultString(currentLog).serializable();
                if (noCapture) {
                    // Diff the partial thing to keep it consistent
                    for (const [k, v] of Object.entries(partial.details)) {
                        if (!(k in prevPartialOutput.details)) {
                            continue;
                        }

                        delete partial.details[k];
                    }
                } else {
                    mutation.target.textContent = "";
                }

                console.debug(JSON.stringify({ partial }));
                prevPartialOutput = { ...prevPartialOutput, ...partial };
            }
        });


        const output = ensureDiv("output");
        output.textContent = "";

        this.observer.observe(output, {
            characterData: false,
            attributes: false,
            childList: true,
            subtree: false,
        });

        return this.observer;
    }

    disconnectObserver() {
        if (this.observer !== null) {
            this.observer.disconnect();
            this.observer = null;
        }
    }

    serializable(): SerializableTestResultContainer {
        return {
            details: JSON.parse(JSON.stringify(this.details)),
            summary: JSON.parse(JSON.stringify(this.summary)),
        };
    }
}

function outputControlDiv(fileName: string, error?: Error): void {
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
}

function ensureDiv(id: string, create: boolean = true): Element {
    let element = document.getElementById(id);
    if (!element && create) {
        element = document.createElement("pre");
        element.id = id;
        document.body.appendChild(element);
    }
    return element;
}

interface RunTestsParams {
    fileName: string;
    tests: string[];
    testFilter?: string;
    args?: string[];
    noCapture?: boolean;
}

async function runTests(params: RunTestsParams): Promise<SerializableTestResultContainer> {
    let listeners: { [key: string]: EventListener };

    const { fileName, tests } = params;
    const testFilter = params.testFilter ?? null;
    const args = params.args ?? null;
    const noCapture = params.noCapture ?? false;

    const testResults = new TestResultContainer();
    // let observerRef;
    const observerRef = testResults.setupObserver(noCapture);

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

        const output = document.getElementById("output");
        if (output) {
            testResults.parseTestResultString(output.textContent);
        }

        console.debug(JSON.stringify({ complete: testResults.serializable(), rawLog: testResults.getRawLog() }));

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

        if (observerRef) {
            observerRef.disconnect();
        }
    }
}

(window as any).__wbg_test_invoke = f => f();
(window as any).runTests = runTests;
