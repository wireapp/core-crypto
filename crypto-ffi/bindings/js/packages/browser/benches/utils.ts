import { browser } from "@wdio/globals";
import type { Bench } from "tinybench";
import { type CommitBundle } from "@wireapp/core-crypto/browser";
import { isNumberObject } from "node:util/types";
import { mkdir } from "node:fs/promises";
import { writeFile } from "node:fs/promises";
import {
    sharedSetup,
    type Helpers,
    type DeliveryService,
} from "../shared/utils";
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

export type CustomBenchmarkEntry = {
    name: string;
    unit: string;
    value: number;
    range?: string;
    extra?: string;
};

function parseMetric(metric?: string | number) {
    if (!metric) return null;

    if (isNumberObject(metric)) {
        return {
            metric,
            range: undefined,
        };
    } else {
        const [rawValue, rawRange] = metric
            .split("±")
            .map((part) => part.trim());

        const value =
            rawValue !== undefined ? Number.parseFloat(rawValue) : undefined;

        if (Number.isNaN(value)) return null;

        return {
            value,
            range: rawRange,
        };
    }
}

export function toCustomBenchmarkEntries(
    benchmarkName: string | undefined,
    rows: (Record<string, string | number | undefined> | null)[]
): CustomBenchmarkEntry[] {
    return rows.map((row) => {
        const throughput = parseMetric(row?.["Throughput avg (ops/s)"]);
        const extra = [
            row?.["Latency avg (ns)"]
                ? `Average Latency (ns): ${row["Latency avg (ns)"]}`
                : null,
            row?.["Latency med (ns)"]
                ? `Median Latency (ns): ${row["Latency med (ns)"]}`
                : null,
            row?.["Throughput med (ops/s)"]
                ? `Median Throughput (ops/s): ${row["Throughput med (ops/s)"]}`
                : null,
            row?.["Samples"] !== undefined
                ? `Samples: ${row["Samples"]}`
                : null,
        ]
            .filter(Boolean)
            .join("\n");

        return {
            name: `${benchmarkName} - ${row?.["Task name"]}`,
            unit: "ops/s",
            value: throughput?.value ?? 0,
            range: throughput?.range,
            extra: extra || undefined,
        };
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

    console.log(results.name);
    console.log(results.table);

    if (!process.env["CI"]) return;

    const customResults = toCustomBenchmarkEntries(results.name, results.table);

    await mkdir("benches_result", { recursive: true });
    await writeFile(
        `benches_result/${results.name}.json`,
        JSON.stringify(customResults, null, 2)
    );
}
