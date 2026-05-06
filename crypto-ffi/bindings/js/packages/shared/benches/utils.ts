import type { Task } from "tinybench";
import { CipherSuite } from "../src/CoreCrypto";
import { isNumberObject } from "node:util/types";
import { mkdir } from "node:fs/promises";
import { writeFile } from "node:fs/promises";

export function tinybenchSetup(task?: Task, mode?: string) {
    console.log(`Executing ${mode} ${task?.name}`);
}

type MessageParameterSet = {
    count: number;
    size: number;
    cipherSuite: number;
};

const DEFAULT_MESSAGE_COUNTS = [1, 10, 100];
const DEFAULT_MESSAGE_SIZES = [16, 1024, 65536];
const DEFAULT_USER_COUNTS = [1, 10, 100];
const DEFAULT_CIPHER_SUITES = [
    CipherSuite.Mls128Dhkemx25519Aes128gcmSha256Ed25519,
    CipherSuite.Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519,
    CipherSuite.Mls128Dhkemp256Aes128gcmSha256P256,
    CipherSuite.Mls256Dhkemp384Aes256gcmSha384P384,
    CipherSuite.Mls256Dhkemp521Aes256gcmSha512P521,
];

function parsePositiveIntegerList(
    envVarName: string,
    fallback: number[]
): number[] {
    const rawValue = process.env[envVarName];

    if (rawValue === undefined || rawValue.trim() === "") {
        return fallback;
    }

    const values = rawValue.split(",").map((value) => value.trim());
    return values.map((value) => Number.parseInt(value, 10));
}

function parseCipherSuiteList(
    envVarName: string,
    fallback: number[]
): number[] {
    const rawValue = process.env[envVarName];

    if (rawValue === undefined || rawValue.trim() === "") {
        return fallback;
    }

    const values = rawValue.split(",").map((value) => value.trim());
    return values.map((value) => {
        const cipherSuite = CipherSuite[value as keyof typeof CipherSuite];
        if (typeof cipherSuite !== "number") {
            throw new Error(`Invalid ciphersuite override: ${value}`);
        }
        return cipherSuite;
    });
}

export async function messageBenchmarkParameters(): Promise<
    MessageParameterSet[]
> {
    const messageCounts = parsePositiveIntegerList(
        "BENCHMARK_MESSAGE_COUNTS",
        DEFAULT_MESSAGE_COUNTS
    );
    const messageSizes = parsePositiveIntegerList(
        "BENCHMARK_MESSAGE_SIZES",
        DEFAULT_MESSAGE_SIZES
    );
    const cipherSuites = parseCipherSuiteList(
        "BENCHMARK_CIPHER_SUITES",
        DEFAULT_CIPHER_SUITES
    );

    function* benchmarkCombinations() {
        for (const count of messageCounts) {
            for (const size of messageSizes) {
                for (const cipherSuite of cipherSuites) {
                    yield { count, size, cipherSuite };
                }
            }
        }
    }

    return Array.from(benchmarkCombinations()) as MessageParameterSet[]; // return as plain array
}

type UserParameterSet = {
    userCount: number;
    cipherSuite: number;
};

export async function userBenchmarkParameters(): Promise<UserParameterSet[]> {
    const userCounts = parsePositiveIntegerList(
        "BENCHMARK_USER_COUNTS",
        DEFAULT_USER_COUNTS
    );
    const cipherSuites = parseCipherSuiteList(
        "BENCHMARK_CIPHER_SUITES",
        DEFAULT_CIPHER_SUITES
    );

    function* benchmarkCombinations() {
        for (const userCount of userCounts) {
            for (const cipherSuite of cipherSuites) {
                yield { userCount, cipherSuite };
            }
        }
    }

    return Array.from(benchmarkCombinations()) as UserParameterSet[]; // return as plain array
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

export async function logResults(
    benchmarkName: string | undefined,
    rows: (Record<string, string | number | undefined> | null)[]
) {
    console.log(benchmarkName);
    console.table(rows);

    if (!process.env["CI"]) return;

    const customResults = toCustomBenchmarkEntries(benchmarkName, rows);

    await mkdir("benches_result", { recursive: true });
    await writeFile(
        `benches_result/${benchmarkName}.json`,
        JSON.stringify(customResults, null, 2)
    );
}
