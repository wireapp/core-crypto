import {
    logResults,
    setup as sharedSetup,
} from "../../../shared/benches/utils";
import { sharedTeardown as tinybenchTeardown } from "../shared/utils";

async function setup() {
    await sharedSetup();
    if (globalThis.tinybench === undefined) {
        globalThis.tinybench = await import("tinybench");
    }

    if (globalThis.tinybenchTeardown === undefined) {
        globalThis.tinybenchTeardown = tinybenchTeardown;
    }
}

export async function runBenchmark(benchmarkSetup: () => Promise<void>) {
    await setup();
    await benchmarkSetup();
    console.log(`Starting ${bench.name}`);
    await bench.run();
    await logResults(bench.name, bench.table());
}
