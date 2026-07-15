import {
    logResults,
    tinybenchSetup,
    userBenchmarkParameters,
    setup,
    teardown,
} from "../../../shared/benches/utils";
import {
    CipherSuite,
    ClientId,
    type KeyPackage,
} from "@wireapp/core-crypto/native";
import { Bench } from "tinybench";

async function run() {
    await setup();
    const parameters = await userBenchmarkParameters();

    const bench = new Bench({
        name: "Removing a User",
        time: 0,
        iterations: 10,
        warmup: true,
        warmupIterations: 1,
        warmupTime: 0,
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
                const clientIdsToRemove: ClientId[] = [];

                for (let i = 0; i < userCount; i++) {
                    const bobId = helpers.newClientId();
                    const bobCc = await helpers.ccInit({
                        withBasicCredential: true,
                        cipherSuite,
                        clientId: bobId,
                    });
                    const kp = await helpers.generateKeyPackage(
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

                const start = bench.now();
                await aliceCc.transaction(
                    async (ctx) =>
                        await ctx.removeClientsFromConversation(
                            conversationId,
                            clientIdsToRemove
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
