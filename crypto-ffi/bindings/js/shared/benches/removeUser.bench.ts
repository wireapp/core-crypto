import type { ClientId, KeyPackage } from "#core-crypto";
import type { ClientWithDatabase } from "../shared/utils";
import { runOnPlatform } from "#shared-utils";
import { runBenchmark, userBenchmarkParameters } from "./utils";

export async function setupRemoveUserBench() {
    const parameters = await userBenchmarkParameters();

    await runOnPlatform(async (parameters) => {
        globalThis.bench = new tinybench.Bench({
            name: "RemoveUser",
            time: 0,
            iterations: 10,
            warmup: true,
            warmupIterations: 1,
            warmupTime: 0,
            setup: globalThis.tinybenchSetup,
            teardown: globalThis.tinybenchTeardown,
        });
        for (const { userCount, cipherSuite, cipherSuiteLabel } of parameters) {
            // Users only provide key packages, so each task creates them once and every
            // iteration adds them to a new conversation with fresh key packages.
            let users: (ClientWithDatabase & { id: ClientId })[] = [];
            bench.add(
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
                        await alice.cc.transaction(
                            async (ctx) =>
                                await ctx.addClientsToConversation(
                                    conversationId,
                                    keyPackages,
                                ),
                        );

                        const start = bench.now();
                        await alice.cc.transaction(
                            async (ctx) =>
                                await ctx.removeClientsFromConversation(
                                    conversationId,
                                    users.map((user) => user.id),
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
                            const id = helpers.newClientId();
                            users.push({
                                ...(await helpers.newClient(cipherSuite, id)),
                                id,
                            });
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
    await runBenchmark(setupRemoveUserBench);
}

await run();
