import { beforeEach, describe } from "mocha";
import { browser } from "@wdio/globals";
import { collect_benchmark_results, setup } from "./utils";
import { userBenchmarkParameters } from "../../shared/benches/utils";
import { type ClientId, type KeyPackage } from "@wireapp/core-crypto/browser";

beforeEach(async () => {
    await setup();
});

describe("benchmark", () => {
    it(`Remove User`, async () => {
        // Initialize the benchmark in the browser, but don't block
        const parameters = await userBenchmarkParameters();
        await browser.execute(async (parameters) => {
            window.benchRunning = true;

            void (async (parameters) => {
                window.bench = new window.tinybench.Bench({
                    name: "Adding a User",
                    time: 1000,
                    iterations: 5,
                    warmupIterations: 1,
                });
                for (const { userCount, cipherSuite } of parameters) {
                    window.bench.add(
                        `cipherSuite=${window.ccModule.Ciphersuite[cipherSuite]} userCount=${userCount}`,
                        async () => {
                            const aliceCc = await window.helpers.ccInit(
                                true,
                                cipherSuite
                            );

                            const conversationId =
                                await window.helpers.createConversation(
                                    aliceCc
                                );
                            const keyPackages: KeyPackage[] = [];
                            const clientIdsToRemove: ClientId[] = [];

                            for (let i = 0; i < userCount; i++) {
                                const bobId = window.helpers.newClientId();
                                const bobCc = await window.helpers.ccInit(
                                    true,
                                    cipherSuite,
                                    bobId
                                );
                                const kp =
                                    await window.helpers.generateKeyPackage(
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
                            const start = window.bench.now();

                            await aliceCc.transaction(
                                async (ctx) =>
                                    await ctx.removeClientsFromConversation(
                                        conversationId,
                                        clientIdsToRemove
                                    )
                            );

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
