import {
    tinybench_setup,
    userBenchmarkParameters,
} from "../../shared/benches/utils";
import {
    Ciphersuite,
    ClientId,
    ConversationId,
    type KeyPackage,
    Credential,
    CredentialType,
} from "@wireapp/core-crypto/native";
import { Bench } from "tinybench";
import { setup, ccInit, teardown } from "../test/utils";

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
                const aliceId = new ClientId(
                    Buffer.from(crypto.randomUUID()).buffer
                );
                const aliceCc = await ccInit(aliceId);

                const aliceCredential = Credential.basic(cipherSuite, aliceId);

                await aliceCc.transaction(async (ctx) => {
                    await ctx.addCredential(aliceCredential);
                });
                const conversationIdStr = crypto.randomUUID();
                const conversationId = new ConversationId(
                    new TextEncoder().encode(conversationIdStr).buffer
                );

                await aliceCc.transaction(async (ctx) => {
                    const [credentialRef] = await ctx.getCredentials();
                    await ctx.createConversation(
                        conversationId,
                        credentialRef!
                    );
                });

                const keyPackages: KeyPackage[] = [];
                const clientIdsToRemove: ClientId[] = [];

                for (let i = 0; i < userCount; i++) {
                    const bobId = new ClientId(
                        Buffer.from(crypto.randomUUID()).buffer
                    );
                    const bobCc = await ccInit(bobId);

                    const bobCredential = Credential.basic(cipherSuite, bobId);

                    await bobCc.transaction(async (ctx) => {
                        await ctx.addCredential(bobCredential);
                    });

                    const kp = await bobCc.transaction(async (ctx) => {
                        const [credentialRef] = await ctx.findCredentials({
                            ciphersuite: cipherSuite,
                            credentialType: CredentialType.Basic,
                        });
                        return await ctx.generateKeyPackage(credentialRef!);
                    });

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
