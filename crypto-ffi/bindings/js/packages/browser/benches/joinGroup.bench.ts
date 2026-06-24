import { beforeEach, describe } from "mocha";
import { browser } from "@wdio/globals";
import { collectBenchmarkResults, setup } from "./utils";
import { userBenchmarkParameters } from "../../../shared/benches/utils";
import type { KeyPackage } from "@wireapp/core-crypto/browser";

beforeEach(async () => {
    await setup();
});

describe("benchmark", () => {
    it(`Join Group`, async () => {
        // 1. Initialize the benchmark in the browser, but don't block
        const parameters = await userBenchmarkParameters();
        await browser.execute(async (parameters) => {
            benchRunning = true;

            void (async (parameters) => {
                bench = new tinybench.Bench({
                    name: "Adding a User",
                    time: 1000,
                    iterations: 5,
                    warmupIterations: 1,
                });
                for (const { userCount, cipherSuite } of parameters) {
                    bench.add(
                        `cipherSuite=${ccModule.CipherSuite[cipherSuite]} userCount=${userCount}`,
                        async () => {
                            const aliceCc = await helpers.ccInit({
                                withBasicCredential: true,
                                cipherSuite,
                            });

                            const conversationId =
                                await helpers.createConversation(aliceCc);
                            const keyPackages: KeyPackage[] = [];

                            if (userCount > 1) {
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

                                await aliceCc.transaction(
                                    async (ctx) =>
                                        await ctx.addClientsToConversation(
                                            conversationId,
                                            keyPackages
                                        )
                                );
                            }

                            const charlieCc = await helpers.ccInit({
                                withBasicCredential: true,
                                cipherSuite,
                            });
                            const kp = await helpers.generateKeyPackage(
                                charlieCc,
                                cipherSuite
                            );

                            await aliceCc.transaction(
                                async (ctx) =>
                                    await ctx.addClientsToConversation(
                                        conversationId,
                                        [kp]
                                    )
                            );
                            const commitBundle =
                                await deliveryService.getLatestCommitBundle();

                            const start = bench.now();

                            await charlieCc.transaction((ctx) =>
                                ctx.processWelcomeMessage(commitBundle.welcome!)
                            );

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
