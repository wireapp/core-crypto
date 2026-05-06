import { browser } from "@wdio/globals";
import type { Bench } from "tinybench";
import type { CommitBundle } from "@wireapp/core-crypto/browser";
import {
    sharedSetup,
    type Helpers,
    type DeliveryService,
} from "../shared/utils";
import { logResults } from "../../shared/benches/utils";
type ccModuleType = typeof import("@wireapp/core-crypto/browser");
declare global {
    interface Window {
        ccModule: ccModuleType;
        deliveryService: DeliveryService;
        _latestCommitBundle: CommitBundle;
        tinybench: typeof import("tinybench");
        benchRunning: boolean;
        bench: Bench;
        helpers: Helpers;
    }
}

export async function setup() {
    await sharedSetup();
    await browser.execute(async () => {
        if (window.tinybench === undefined) {
            window.tinybench =
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
            return !(await browser.execute(() => window.benchRunning));
        },
        {
            timeout: 3_600_000, // 1hr
            timeoutMsg: "Benchmark did not finish in time",
        }
    );

    // 3. Retrieve results
    const results = await browser.execute(() => {
        return { name: window.bench.name, table: window.bench.table() };
    });

    await logResults(results.name, results.table);
}
