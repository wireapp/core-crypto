import { beforeEach, describe } from "mocha";
import { browser } from "@wdio/globals";
import { setup, toCustomBenchmarkEntries } from "./utils";
import { messageBenchmarkParameters } from "../../shared/benches/utils";
import { writeFile, mkdir } from "fs/promises";

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
                    const aliceCc = await window.helpers.setupCc(cipherSuite);
                    const bobCc = await window.helpers.setupCc(cipherSuite);

                    const conversationIdStr = window.crypto.randomUUID();
                    const conversationId = new window.ccModule.ConversationId(
                        new TextEncoder().encode(conversationIdStr).buffer
                    );

                    await aliceCc.transaction(async (ctx) => {
                        const [credentialRef] = await ctx.getCredentials();
                        await ctx.createConversation(
                            conversationId,
                            credentialRef!
                        );
                    });

                    const kp = await bobCc.transaction(async (ctx) => {
                        const [credentialRef] = await ctx.findCredentials({
                            ciphersuite: cipherSuite,
                            credentialType:
                                window.ccModule.CredentialType.Basic,
                        });
                        return await ctx.generateKeyPackage(credentialRef!);
                    });

                    await aliceCc.transaction(
                        async (ctx) =>
                            await ctx.addClientsToConversation(conversationId, [
                                kp,
                            ])
                    );
                    const commitBundle =
                        await window.deliveryService.getLatestCommitBundle();

                    await bobCc.transaction(
                        async (ctx) =>
                            await ctx.processWelcomeMessage(
                                commitBundle.welcome!
                            )
                    );

                    const message = new Uint8Array(size);

                    // Multiple iterations of a benchmark happen on the same cc instances. This means that we can't encrypt the messages beforehand as this would lead to bob decrypting the same messages over and over again.
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
