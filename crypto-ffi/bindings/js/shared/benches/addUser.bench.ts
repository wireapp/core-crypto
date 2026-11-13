import type { KeyPackage } from "#core-crypto";
import type { ClientWithDatabase } from "../shared/utils";
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
            let users: ClientWithDatabase[] = [];
            globalThis.bench.add(
                `cipherSuite=${cipherSuiteLabel} userCount=${userCount}`,
                async () => {
                    const alice = await helpers.newClient(cipherSuite);
                    try {
                        const conversationId = await helpers.createConversation(
                            alice.cc,
                        );
                        const keyPackages: KeyPackage[] = [];
                        for (const user of users) {
                            keyPackages.push(
                                await helpers.generateKeyPackage(
                                    user.cc,
                                    cipherSuite,
                                ),
                            );
                        }

                        const start = bench.now();
                        await alice.cc.transaction(
                            async (ctx) =>
                                await ctx.addClientsToConversation(
                                    conversationId,
                                    keyPackages,
                                ),
                        );
                        const end = bench.now();
                        return { overriddenDuration: end - start };
                    } finally {
                        helpers.releaseClients([alice]);
                    }
                },
                {
                    async beforeAll() {
                        for (let i = 0; i < userCount; i++) {
                            users.push(await helpers.newClient(cipherSuite));
                        }
                    },
                    async afterAll() {
                        helpers.releaseClients(users);
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
