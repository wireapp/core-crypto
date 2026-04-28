import { beforeEach, describe } from "mocha";
import { browser } from "@wdio/globals";
import { collect_benchmark_results, setup } from "./utils";
import { messageBenchmarkParameters } from "../../shared/benches/utils";

beforeEach(async () => {
    await setup();
});

describe("benchmark", () => {
    it(`create messages`, async () => {
        // Initialize the benchmark in the browser, but don't block
        // For long runnning tasks we can't synchronously wait for `browser.execute()` to finish.
        // If the function runs longer than 60s the browser will timeout unrelated to wdio/mocha timeout configs.

        const parameters = await messageBenchmarkParameters();
        await browser.execute(async (parameters) => {
            window.benchRunning = true;
            void (async (parameters) => {
                window.bench = new window.tinybench.Bench({
                    name: "create message",
                    time: 1000,
                    iterations: 5,
                    warmupIterations: 1,
                });
                for (const { count, size, cipherSuite } of parameters) {
                    const message = new Uint8Array(size);
                    const cc = await window.helpers.ccInit({
                        withBasicCredential: true,
                        cipherSuite,
                    });

                    const conversationId =
                        await window.helpers.createConversation(cc);

                    window.bench.add(
                        `cipherSuite=${window.ccModule.Ciphersuite[cipherSuite]} size=${size}B count=${count}`,
                        async () => {
                            await cc.transaction(async (ctx) => {
                                for (let i = 0; i < count; i++) {
                                    await ctx.encryptMessage(
                                        conversationId,
                                        message!.buffer
                                    );
                                }
                            });
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
