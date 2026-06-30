import {
    logResults,
    tinybenchSetup,
    userBenchmarkParameters,
    setup,
    teardown,
} from "../../../shared/benches/utils";
import { CipherSuite, type KeyPackage } from "@wireapp/core-crypto/native";
import { Bench } from "tinybench";

async function run() {
    await setup();
    const parameters = await userBenchmarkParameters();

    const bench = new Bench({
        name: "Adding a User",
        time: 1000,
        iterations: 5,
        warmupIterations: 1,
        setup: tinybenchSetup,
        teardown: teardown,
    });
    for (const { userCount, cipherSuite } of parameters) {
        bench.add(
            `cipherSuite=${CipherSuite[cipherSuite]} userCount=${userCount}`,
            async () => {
                const aliceCc = await helpers.ccInit({
                    withBasicCredential: true,
                    cipherSuite,
                });
                const conversationId =
                    await helpers.createConversation(aliceCc);
                const keyPackages: KeyPackage[] = [];

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

                const start = bench.now();
                await aliceCc.transaction(
                    async (ctx) =>
                        await ctx.addClientsToConversation(
                            conversationId,
                            keyPackages
                        )
                );
                const end = bench.now();
                return { overriddenDuration: end - start };
            }
        );
    }

    console.log(`Starting ${bench.name}`);
    await bench.run();

    await logResults(bench.name, bench.table());
}

await run();
