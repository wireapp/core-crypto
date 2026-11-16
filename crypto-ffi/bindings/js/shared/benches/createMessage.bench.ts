import { runOnPlatform } from "#shared-utils";
import { messageBenchmarkParameters, runBenchmark } from "./utils";

export async function setupCreateMessageBench() {
    const parameters = await messageBenchmarkParameters();
    await runOnPlatform(async (parameters) => {
        globalThis.bench = newBench("CreateMessage");

        for (const { count, size, cipherSuite, taskName } of parameters) {
            const message = new Uint8Array(size);
            const cc = await helpers.ccInit({
                withBasicCredential: true,
                cipherSuite,
            });
            const conversationId = await helpers.createConversation(cc);

            bench.add(taskName, async () => {
                await cc.transaction(async (ctx) => {
                    for (let i = 0; i < count; i++) {
                        await ctx.encryptMessage(conversationId, message);
                    }
                });
            });
        }
    }, parameters);
}

async function run() {
    await runBenchmark(setupCreateMessageBench);
}

await run();
