import type { Task } from "tinybench";
import { Ciphersuite } from "../src/CoreCrypto";

export function tinybench_setup(task?: Task, mode?: string) {
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
    Ciphersuite.Mls128Dhkemx25519Aes128gcmSha256Ed25519,
    Ciphersuite.Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519,
    Ciphersuite.Mls128Dhkemp256Aes128gcmSha256P256,
    Ciphersuite.Mls256Dhkemp384Aes256gcmSha384P384,
    Ciphersuite.Mls256Dhkemp521Aes256gcmSha512P521,
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
        const cipherSuite = Ciphersuite[value as keyof typeof Ciphersuite];
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
