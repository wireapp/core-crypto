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

export async function messageBenchmarkParameters(): Promise<MessageParameterSet[]> {
    const messageCounts = [1, 10, 100];
    const messageSizes = [16, 1024, 65536];
    const cipherSuites = [
        Ciphersuite.Mls128Dhkemx25519Aes128gcmSha256Ed25519,
        Ciphersuite.Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519,
        Ciphersuite.Mls128Dhkemp256Aes128gcmSha256P256,
        Ciphersuite.Mls256Dhkemp384Aes256gcmSha384P384,
        Ciphersuite.Mls256Dhkemp521Aes256gcmSha512P521,
    ];

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
