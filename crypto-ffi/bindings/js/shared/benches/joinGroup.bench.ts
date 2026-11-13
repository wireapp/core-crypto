import type { KeyPackage } from "#core-crypto";
import type { ClientWithDatabase } from "../shared/utils";
import { runOnPlatform } from "#shared-utils";
import { runBenchmark, userBenchmarkParameters } from "./utils";

export async function setupJoinGroupBench() {
    const parameters = await userBenchmarkParameters();
    await runOnPlatform(async (parameters) => {
        globalThis.bench = new tinybench.Bench({
            name: "JoinGroup",
            time: 1000,
            iterations: 5,
            warmupIterations: 1,
            setup: globalThis.tinybenchSetup,
            teardown: globalThis.tinybenchTeardown,
        });
        for (const { userCount, cipherSuite, cipherSuiteLabel } of parameters) {
            // The existing members only provide key packages, so each task creates them
            // once and every iteration takes fresh key packages from them.
            let members: ClientWithDatabase[] = [];
            bench.add(
                `cipherSuite=${cipherSuiteLabel} userCount=${userCount}`,
                async () => {
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

                        const start = bench.now();
                        await charlie.cc.transaction((ctx) =>
                            ctx.processWelcomeMessage(commitBundle.welcome!),
                        );
                        const end = bench.now();
                        return { overriddenDuration: end - start };
                    } finally {
                        helpers.releaseClients([alice, charlie]);
                    }
                },
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
