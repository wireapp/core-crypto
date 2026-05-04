import { Bench } from "tinybench";
import { Ciphersuite } from "@wireapp/core-crypto/native";
import {
    messageBenchmarkParameters,
    tinybench_setup,
} from "../../shared/benches/utils";
import {
    ccInit,
    setup,
    teardown,
    createConversation,
    invite,
} from "../test/utils";

async function run() {
    await setup();
    const parameters = await messageBenchmarkParameters();
    const bench = new Bench({
        name: "Process Messages Benchmark",
        time: 1000,
        iterations: 5,
        warmupIterations: 1,
        setup: tinybench_setup,
        teardown: teardown,
    });

    for (const { count, size, cipherSuite } of parameters) {
        const aliceCc = await ccInit({
            withBasicCredential: true,
            cipherSuite,
        });

        const bobCc = await ccInit({ withBasicCredential: true, cipherSuite });
        const conversationId = await createConversation(aliceCc);

        await invite(aliceCc, bobCc, conversationId, cipherSuite);

        const message = new Uint8Array(size);

        // Multiple iterations of a benchmark happen on the same cc instances.
        // This means that we can't encrypt the messages beforehand as this would lead to bob decrypting
        // the same messages over and over again.
        bench.add(
            `cipherSuite=${Ciphersuite[cipherSuite]} size=${size}B count=${count}`,
            async () => {
                const encryptedMessages = await aliceCc.transaction(
                    async (ctx) => {
                        const encryptedMessages: ArrayBuffer[] = [];
                        for (let i = 0; i < count; i++) {
                            const encryptedMessage = await ctx.encryptMessage(
                                conversationId,
                                message.buffer
                            );

                            encryptedMessages.push(encryptedMessage);
                        }
                        return encryptedMessages;
                    }
                );
                const start = bench.now();
                await bobCc.transaction(async (ctx) => {
                    for (const message of encryptedMessages) {
                        await ctx.decryptMessage(conversationId, message);
                    }
                });
                const end = bench.now();
                return { overriddenDuration: end - start };
            }
        );
    }

    console.log(`Starting ${bench.name}`);
    await bench.run();

    console.log(bench.name);
    console.table(bench.table());
}

await run();
