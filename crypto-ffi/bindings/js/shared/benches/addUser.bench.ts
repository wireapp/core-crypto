import type { CoreCrypto, KeyPackage } from "#core-crypto";
import { runBenchmark, userBenchmarkParameters } from "./utils";
import { runOnPlatform } from "../shared/utils";

export async function setupAddUserBench() {
    const parameters = await userBenchmarkParameters();
    await runOnPlatform(async (parameters) => {
        globalThis.bench = new globalThis.tinybench.Bench({
            name: "AddUser",
            time: 1000,
            iterations: 5,
            warmupIterations: 1,
            setup: globalThis.tinybenchSetup,
            teardown: globalThis.tinybenchTeardown,
        });
        for (const { userCount, cipherSuite, cipherSuiteLabel } of parameters) {
            // Users only provide key packages, so each task creates them once and every
            // iteration takes fresh key packages from them.
            let users: CoreCrypto[] = [];
            globalThis.bench.add(
                `cipherSuite=${cipherSuiteLabel} userCount=${userCount}`,
                async () => {
                    const alice = await helpers.ccInit({
                        withBasicCredential: true,
                        cipherSuite,
                    });
                    const conversationId =
                        await helpers.createConversation(alice);
                    const keyPackages: KeyPackage[] = [];
                    for (const user of users) {
                        keyPackages.push(
                            await helpers.generateKeyPackage(user, cipherSuite),
                        );
                    }

                    const start = bench.now();
                    await alice.transaction(
                        async (ctx) =>
                            await ctx.addClientsToConversation(
                                conversationId,
                                keyPackages,
                            ),
                    );
                    const end = bench.now();
                    return { overriddenDuration: end - start };
                },
                {
                    async beforeAll() {
                        for (let i = 0; i < userCount; i++) {
                            users.push(
                                await helpers.ccInit({
                                    withBasicCredential: true,
                                    cipherSuite,
                                }),
                            );
                        }
                    },
                    async afterAll() {
                        users = [];
                    },
                },
            );
        }
    }, parameters);
}

async function run() {
    await runBenchmark(setupAddUserBench);
}

await run();
