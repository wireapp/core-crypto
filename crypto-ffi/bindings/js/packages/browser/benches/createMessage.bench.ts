import { beforeEach, describe } from "mocha";
import { browser } from "@wdio/globals";
import { setup, toCustomBenchmarkEntries } from "./utils";
import { benchmarkParameters } from "../../shared/benches/utils";
import { mkdir, writeFile } from "fs/promises";

beforeEach(async () => {
    await setup();
});

describe("benchmark", () => {
    it(`create messages`, async () => {
        // 1. Initialize the benchmark in the browser, but don't block
        // For long runnning tasks we can't synchronously wait for `browser.execute()` to finish.
        // If the function runs longer than 60s the browser will timeout unrelated to wdio/mocha timeout configs.

        const parameters = await benchmarkParameters();
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
                    const cc = await window.helpers.setupCc(cipherSuite);

                    const conversationIdStr = window.crypto.randomUUID();
                    const conversationId = new window.ccModule.ConversationId(
                        new TextEncoder().encode(conversationIdStr).buffer
                    );

                    await cc.transaction(async (ctx) => {
                        const [credentialRef] = await ctx.getCredentials();
                        await ctx.createConversation(
                            conversationId,
                            credentialRef!
                        );
                    });

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

        // 2. Poll until benchmark is done
        await browser.waitUntil(
            async () => {
                return !(await browser.execute(() => window.benchRunning));
            },
            {
                timeout: 1_800_000, // 30 min
                timeoutMsg: "Benchmark did not finish in time",
            }
        );

        // 3. Retrieve results
        const results = await browser.execute(() => {
            return { name: window.bench.name, table: window.bench.table() };
        });

        console.log(results.name);
        console.log(results.table);

        if (!process.env["CI"]) return;

        const customResults = toCustomBenchmarkEntries(
            results.name,
            results.table
        );

        await mkdir("benches_result", { recursive: true });
        await writeFile(
            `benches_result/${results.name}.json`,
            JSON.stringify(customResults, null, 2)
        );
    });
});
