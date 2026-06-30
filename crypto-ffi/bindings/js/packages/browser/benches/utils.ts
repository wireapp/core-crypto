import { browser } from "@wdio/globals";
import type { Bench } from "tinybench";
import {
    logResults,
    setup as sharedSetup,
} from "../../../shared/benches/utils";

declare global {
    var tinybench: typeof import("tinybench");
    var benchRunning: boolean;
    var bench: Bench;
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

/*
Helper method to:
1. Poll until the benchmark is done
2. Retrieve the results
3. Print results and save them to file if in CI
*/
export async function collectBenchmarkResults() {
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
