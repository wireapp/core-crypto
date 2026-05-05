import {
    logResults,
    tinybenchSetup,
    userBenchmarkParameters,
} from "../../shared/benches/utils";
import { Ciphersuite, type KeyPackage } from "@wireapp/core-crypto/native";
import { Bench } from "tinybench";
import {
    setup,
    ccInit,
    teardown,
    DELIVERY_SERVICE,
    createConversation,
    generateKeyPackage,
} from "../test/utils";

async function run() {
    await setup();
    const parameters = await userBenchmarkParameters();

    const bench = new Bench({
        name: "Join Group",
        time: 1000,
        iterations: 5,
        warmupIterations: 1,
        setup: tinybenchSetup,
        teardown: teardown,
    });
    for (const { userCount, cipherSuite } of parameters) {
        bench.add(
            `cipherSuite=${Ciphersuite[cipherSuite]} userCount=${userCount}`,
            async () => {
                const aliceCc = await ccInit({
                    withBasicCredential: true,
                    cipherSuite,
                });

                const conversationId = await createConversation(aliceCc);

                const keyPackages: KeyPackage[] = [];

                if (userCount > 1) {
                    for (let i = 0; i < userCount; i++) {
                        const bobCc = await ccInit({
                            withBasicCredential: true,
                            cipherSuite,
                        });
                        const kp = await generateKeyPackage(bobCc, cipherSuite);
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

                const charlieCc = await ccInit({
                    withBasicCredential: true,
                    cipherSuite,
                });
                const kp = await generateKeyPackage(charlieCc, cipherSuite);
                await aliceCc.transaction(
                    async (ctx) =>
                        await ctx.addClientsToConversation(conversationId, [kp])
                );
                const commitBundle =
                    await DELIVERY_SERVICE.getLatestCommitBundle();

                const start = bench.now();

                await charlieCc.transaction((ctx) =>
                    ctx.processWelcomeMessage(commitBundle.welcome!)
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
