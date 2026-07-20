import type { ClientId, KeyPackage } from "#core-crypto-ffi";
import { runOnPlatform } from "#shared-utils";
import { userBenchmarkParameters } from "./utils";

export async function setupRemoveUserBench() {
    const parameters = await userBenchmarkParameters();

    await runOnPlatform(async (parameters) => {
        globalThis.bench = new tinybench.Bench({
            name: "Removing a User",
            time: 0,
            iterations: 10,
            warmup: true,
            warmupIterations: 1,
            warmupTime: 0,
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
                    const clientIdsToRemove: ClientId[] = [];

                    for (let i = 0; i < userCount; i++) {
                        const bobId = helpers.newClientId();
                        const bobCc = await helpers.ccInit({
                            withBasicCredential: true,
                            cipherSuite,
                            clientId: bobId,
                        });
                        const kp = await helpers.generateKeyPackage(
                            bobCc,
                            cipherSuite
                        );
                        keyPackages.push(kp);
                        clientIdsToRemove.push(bobId);
                    }

                    await aliceCc.transaction(
                        async (ctx) =>
                            await ctx.addClientsToConversation(
                                conversationId,
                                keyPackages
                            )
                    );
                    const start = bench.now();

                    await aliceCc.transaction(
                        async (ctx) =>
                            await ctx.removeClientsFromConversation(
                                conversationId,
                                clientIdsToRemove
                            )
                    );

                    const end = bench.now();
                    return { overriddenDuration: end - start };
                }
            );
        }
    }, parameters);
}
