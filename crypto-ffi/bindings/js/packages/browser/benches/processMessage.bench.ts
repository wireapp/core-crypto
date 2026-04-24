import { beforeEach, describe } from "mocha";
import { browser } from "@wdio/globals";
import { collect_benchmark_results, setup } from "./utils";
import { messageBenchmarkParameters } from "../../shared/benches/utils";

beforeEach(async () => {
    await setup();
});

describe("benchmark", () => {
    it(`process messages`, async () => {
        // 1. Initialize the benchmark in the browser, but don't block
        const parameters = await messageBenchmarkParameters();
        await browser.execute(async (parameters) => {
            window.benchRunning = true;

            void (async (parameters) => {
                window.bench = new window.tinybench.Bench({
                    name: "process message",
                    time: 1000,
                    iterations: 5,
                    warmupIterations: 1,
                });
                for (const { count, size, cipherSuite } of parameters) {
                    const aliceCc = await window.helpers.ccInit(
                        true,
                        cipherSuite
                    );
                    const bobCc = await window.helpers.ccInit(
                        true,
                        cipherSuite
                    );

                    const conversationId =
                        await window.helpers.createConversation(aliceCc);

                    await window.helpers.invite(
                        aliceCc,
                        bobCc,
                        conversationId,
                        cipherSuite
                    );

                    const message = new Uint8Array(size);

                    // Multiple iterations of a benchmark happen on the same cc instances.
                    // This means that we can't encrypt the messages beforehand as this would lead to bob decrypting
                    // the same messages over and over again.
                    window.bench.add(
                        `cipherSuite=${window.ccModule.Ciphersuite[cipherSuite]} size=${size}B count=${count}`,
                        async () => {
                            const encryptedMessages = await aliceCc.transaction(
                                async (ctx) => {
                                    const encryptedMessages: ArrayBuffer[] = [];
                                    for (let i = 0; i < count; i++) {
                                        const encryptedMessage =
                                            await ctx.encryptMessage(
                                                conversationId,
                                                message.buffer
                                            );

                                        encryptedMessages.push(
                                            encryptedMessage
                                        );
                                    }
                                    return encryptedMessages;
                                }
                            );
                            const start = window.bench.now();
                            await bobCc.transaction(async (ctx) => {
                                for (const message of encryptedMessages) {
                                    await ctx.decryptMessage(
                                        conversationId,
                                        message
                                    );
                                }
                            });
                            const end = window.bench.now();
                            return { overriddenDuration: end - start };
                        }
                    );
                }

                await window.bench.run();
                window.benchRunning = false;
            })(parameters);
        }, parameters);

        await collect_benchmark_results();
    });
});
