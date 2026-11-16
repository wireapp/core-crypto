import type { KeyPackage } from "#core-crypto";
import type { ClientWithDatabase } from "../shared/utils";
import { runBenchmark, userBenchmarkParameters } from "./utils";
import { runOnPlatform } from "../shared/utils";

export async function setupAddUserBench() {
    const parameters = await userBenchmarkParameters();
    await runOnPlatform(async (parameters) => {
        globalThis.bench = newBench("AddUser");
        for (const { userCount, cipherSuite, taskName } of parameters) {
            // Users only provide key packages, so each task creates them once and every
            // iteration takes fresh key packages from them.
            let users: ClientWithDatabase[] = [];
            globalThis.bench.add(
                taskName,
                measured(async (measure) => {
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

                        await measure(() =>
                            alice.cc.transaction(
                                async (ctx) =>
                                    await ctx.addClientsToConversation(
                                        conversationId,
                                        keyPackages,
                                    ),
                            ),
                        );
                    } finally {
                        helpers.releaseClients([alice]);
                    }
                }),
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
