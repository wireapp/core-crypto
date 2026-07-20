import type { KeyPackage } from "#core-crypto";
import { runOnPlatform } from "#shared-utils";
import { userBenchmarkParameters } from "./utils";

export async function setupJoinGroupBench() {
    const parameters = await userBenchmarkParameters();
    await runOnPlatform(async (parameters) => {
        globalThis.bench = new tinybench.Bench({
            name: "Join a Group",
            time: 1000,
            iterations: 5,
            warmupIterations: 1,
            setup: globalThis.tinybenchSetup,
            teardown: globalThis.tinybenchTeardown,
        });
        for (const { userCount, cipherSuite } of parameters) {
            bench.add(
                `cipherSuite=${ccModule.CipherSuite[cipherSuite]} userCount=${userCount}`,
                async () => {
                    const aliceCc = await helpers.ccInit({
                        withBasicCredential: true,
                        cipherSuite,
                    });

                    const conversationId =
                        await helpers.createConversation(aliceCc);
                    const keyPackages: KeyPackage[] = [];

                    if (userCount > 1) {
                        for (let i = 0; i < userCount; i++) {
                            const bobCc = await helpers.ccInit({
                                withBasicCredential: true,
                                cipherSuite,
                            });
                            const kp = await helpers.generateKeyPackage(
                                bobCc,
                                cipherSuite
                            );
                            keyPackages.push(kp);
                        }

                        await aliceCc.transaction(
                            async (ctx) =>
                                await ctx.addClientsToConversation(
                                    conversationId,
                                    keyPackages
                                )
                        );
                    }

                    const charlieCc = await helpers.ccInit({
                        withBasicCredential: true,
                        cipherSuite,
                    });
                    const kp = await helpers.generateKeyPackage(
                        charlieCc,
                        cipherSuite
                    );

                    await aliceCc.transaction(
                        async (ctx) =>
                            await ctx.addClientsToConversation(conversationId, [
                                kp,
                            ])
                    );
                    const commitBundle =
                        await deliveryService.getLatestCommitBundle();

                    const start = bench.now();

                    await charlieCc.transaction((ctx) =>
                        ctx.processWelcomeMessage(commitBundle.welcome!)
                    );

                    const end = bench.now();
                    return { overriddenDuration: end - start };
                }
            );
        }
    }, parameters);
}
