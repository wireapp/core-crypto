import {
    tinybench_setup,
    userBenchmarkParameters,
} from "../../shared/benches/utils";
import {
    Ciphersuite,
    ClientId,
    type KeyPackage,
} from "@wireapp/core-crypto/native";
import { Bench } from "tinybench";
import {
    setup,
    ccInit,
    teardown,
    createConversation,
    generateKeyPackage,
} from "../test/utils";

async function run() {
    await setup();
    const parameters = await userBenchmarkParameters();

    const bench = new Bench({
        name: "Removing a User",
        time: 1000,
        iterations: 5,
        warmupIterations: 1,
        setup: tinybench_setup,
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
                const clientIdsToRemove: ClientId[] = [];

                for (let i = 0; i < userCount; i++) {
                    const bobId = new ClientId(
                        Buffer.from(crypto.randomUUID()).buffer
                    );
                    const bobCc = await ccInit({
                        withBasicCredential: true,
                        cipherSuite,
                        clientId: bobId,
                    });
                    const kp = await generateKeyPackage(bobCc, cipherSuite);

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

    console.log(bench.name);
    console.table(bench.table());
}

await run();
