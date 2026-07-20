import { runOnPlatform } from "#shared-utils";
import { messageBenchmarkParameters } from "./utils";

export async function setupCreateMessageBench() {
    const parameters = await messageBenchmarkParameters();
    await runOnPlatform(async (parameters) => {
        globalThis.bench = new tinybench.Bench({
            name: "Create Messages",
            time: 1000,
            iterations: 5,
            warmupIterations: 1,
            setup: globalThis.tinybenchSetup,
            teardown: globalThis.tinybenchTeardown,
        });

        for (const { count, size, cipherSuite } of parameters) {
            const message = new Uint8Array(size);
            const cc = await helpers.ccInit({
                withBasicCredential: true,
                cipherSuite,
            });
            const conversationId = await helpers.createConversation(cc);

            bench.add(
                `cipherSuite=${ccModule.CipherSuite[cipherSuite]} size=${size}B count=${count}`,
                async () => {
                    await cc.transaction(async (ctx) => {
                        for (let i = 0; i < count; i++) {
                            await ctx.encryptMessage(conversationId, message);
                        }
                    });
                }
            );
        }
    }, parameters);
}
