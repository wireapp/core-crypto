import type { KeyPackage } from "#core-crypto";
import type { ClientWithDatabase } from "../shared/utils";
import { runOnPlatform } from "#shared-utils";
import { runBenchmark, userBenchmarkParameters } from "./utils";

export async function setupJoinGroupBench() {
    const parameters = await userBenchmarkParameters();
    await runOnPlatform(async (parameters) => {
        globalThis.bench = newBench("JoinGroup");
        for (const { userCount, cipherSuite, taskName } of parameters) {
            // The existing members only provide key packages, so each task creates them
            // once and every iteration takes fresh key packages from them.
            let members: ClientWithDatabase[] = [];
            bench.add(
                taskName,
                measured(async (measure) => {
                    const alice = await helpers.newClient(cipherSuite);
                    const charlie = await helpers.newClient(cipherSuite);
                    try {
                        const conversationId = await helpers.createConversation(
                            alice.cc,
                        );

                        if (members.length > 0) {
                            const keyPackages: KeyPackage[] = [];
                            for (const member of members) {
                                keyPackages.push(
                                    await helpers.generateKeyPackage(
                                        member.cc,
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
                        }

                        const kp = await helpers.generateKeyPackage(
                            charlie.cc,
                            cipherSuite,
                        );
                        await alice.cc.transaction(
                            async (ctx) =>
                                await ctx.addClientsToConversation(
                                    conversationId,
                                    [kp],
                                ),
                        );
                        const commitBundle =
                            await deliveryService.getLatestCommitBundle();

                        await measure(() =>
                            charlie.cc.transaction((ctx) =>
                                ctx.processWelcomeMessage(
                                    commitBundle.welcome!,
                                ),
                            ),
                        );
                    } finally {
                        helpers.releaseClients([alice, charlie]);
                    }
                }),
                {
                    async beforeAll() {
                        if (userCount > 1) {
                            for (let i = 0; i < userCount; i++) {
                                members.push(
                                    await helpers.newClient(cipherSuite),
                                );
                            }
                        }
                    },
                    async afterAll() {
                        helpers.releaseClients(members);
                        members = [];
                    },
                },
            );
        }
    }, parameters);
}

async function run() {
    await runBenchmark(setupJoinGroupBench);
}

await run();
