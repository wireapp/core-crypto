import type { KeyPackage } from "#core-crypto";
import { userBenchmarkParameters } from "./utils";
import { runOnPlatform } from "../shared/utils";

export async function setupAddUserBench() {
    const parameters = await userBenchmarkParameters();
    await runOnPlatform(async (parameters) => {
        globalThis.bench = new globalThis.tinybench.Bench({
            name: "Add a User",
            time: 1000,
            iterations: 5,
            warmupIterations: 1,
            setup: globalThis.tinybenchSetup,
            teardown: globalThis.tinybenchTeardown,
        });
        for (const { userCount, cipherSuite } of parameters) {
            globalThis.bench.add(
                `cipherSuite=${ccModule.CipherSuite[cipherSuite]} userCount=${userCount}`,
                async () => {
                    const aliceCc = await helpers.ccInit({
                        withBasicCredential: true,
                        cipherSuite,
                    });

                    const conversationId =
                        await helpers.createConversation(aliceCc);
                    const keyPackages: KeyPackage[] = [];

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

                    const start = bench.now();
                    await aliceCc.transaction(
                        async (ctx) =>
                            await ctx.addClientsToConversation(
                                conversationId,
                                keyPackages
                            )
                    );
                    const end = bench.now();
                    return { overriddenDuration: end - start };
                }
            );
        }
    }, parameters);
}
