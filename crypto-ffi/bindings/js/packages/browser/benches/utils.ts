import {
    logResults,
    setup as sharedSetup,
} from "../../../shared/benches/utils";
import { getPage, setupBrowser, teardownBrowser } from "../shared/utils";

export async function runBenchmark(benchmarkSetup: () => Promise<void>) {
    await setup();
    await benchmarkSetup();
    const results = await getPage().evaluate(async () => {
        await bench.run();
        return { name: bench.name, table: bench.table() };
    });
    await teardown();
    await logResults(results.name, results.table);
}

export async function setup() {
    // We increase the browser timeout for benchmarks
    const protocolTimeout = 60 * 60 * 1000; // 1 hr
    await setupBrowser(protocolTimeout);
    await sharedSetup();
    await getPage().evaluate(async () => {
        if (globalThis.tinybench === undefined) {
            tinybench =
                // @ts-expect-error TS2307: Cannot find module or its corresponding type declarations.
                await import("./node_modules/tinybench/dist/index.js");
        }
    });

    if (globalThis.tinybenchTeardown === undefined) {
        globalThis.tinybenchTeardown = () => {};
    }
}

export async function teardown() {
    await teardownBrowser();
}
