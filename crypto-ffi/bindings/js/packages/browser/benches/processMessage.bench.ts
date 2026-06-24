import { beforeEach, describe } from "mocha";
import { browser } from "@wdio/globals";
import { collectBenchmarkResults, setup } from "./utils";
import { messageBenchmarkParameters } from "../../../shared/benches/utils";

beforeEach(async () => {
    await setup();
});

describe("benchmark", () => {
    it(`process messages`, async () => {
        // 1. Initialize the benchmark in the browser, but don't block
        const parameters = await messageBenchmarkParameters();
        await browser.execute(async (parameters) => {
            benchRunning = true;

            void (async (parameters) => {
                bench = new tinybench.Bench({
                    name: "process message",
                    time: 1000,
                    iterations: 5,
                    warmupIterations: 1,
                });
                for (const { count, size, cipherSuite } of parameters) {
                    const aliceCc = await helpers.ccInit({
                        withBasicCredential: true,
                        cipherSuite,
                    });
                    const bobCc = await helpers.ccInit({
                        withBasicCredential: true,
                        cipherSuite,
                    });

                    const conversationId =
                        await helpers.createConversation(aliceCc);

                    await helpers.invite(
                        aliceCc,
                        bobCc,
                        conversationId,
                        cipherSuite
                    );

                    const message = new Uint8Array(size);

                    // Multiple iterations of a benchmark happen on the same cc instances.
                    // This means that we can't encrypt the messages beforehand as this would lead to bob decrypting
                    // the same messages over and over again.
                    bench.add(
                        `cipherSuite=${ccModule.CipherSuite[cipherSuite]} size=${size}B count=${count}`,
                        async () => {
                            const encryptedMessages = await aliceCc.transaction(
                                async (ctx) => {
                                    const encryptedMessages: Uint8Array[] = [];
                                    for (let i = 0; i < count; i++) {
                                        const encryptedMessage =
                                            await ctx.encryptMessage(
                                                conversationId,
                                                message
                                            );

                                        encryptedMessages.push(
                                            encryptedMessage
                                        );
                                    }
                                    return encryptedMessages;
                                }
                            );
                            const start = bench.now();
                            await bobCc.transaction(async (ctx) => {
                                for (const message of encryptedMessages) {
                                    await ctx.decryptMessage(
                                        conversationId,
                                        message
                                    );
                                }
                            });
                            const end = bench.now();
                            return { overriddenDuration: end - start };
                        }
                    );
                }

                await bench.run();
                benchRunning = false;
            })(parameters);
        }, parameters);

        await collectBenchmarkResults();
    });
});
