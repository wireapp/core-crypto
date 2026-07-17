import { browser } from "@wdio/globals";
import {
    logResults,
    setup as sharedSetup,
} from "../../../shared/benches/utils";

declare global {
    var benchRunning: boolean;
}

export async function runBenchmark(benchmarkSetup: () => Promise<void>) {
    await setup();
    // 1. Initialize the benchmark in the browser, but don't block
    await benchmarkSetup();
    await browser.execute(async () => {
        benchRunning = true;
        void (async () => {
            await bench.run();
            benchRunning = false;
        })();
    });

    // 2. Poll until benchmark is done
    await browser.waitUntil(
        async () => {
            return !(await browser.execute(() => benchRunning));
        },
        {
            timeout: 3_600_000 * 3, // 3 hr
            timeoutMsg: "Benchmark did not finish in time",
        }
    );

    // 3. Retrieve results
    const results = await browser.execute(() => {
        return { name: bench.name, table: bench.table() };
    });

    await logResults(results.name, results.table);
}

export async function setup() {
    await sharedSetup();
    await browser.execute(async () => {
        if (globalThis.tinybench === undefined) {
            tinybench =
                // @ts-expect-error TS2307: Cannot find module ./corecrypto.js or its corresponding type declarations.
                await import("/node_modules/tinybench/dist/index.js");
        }
    });
}
