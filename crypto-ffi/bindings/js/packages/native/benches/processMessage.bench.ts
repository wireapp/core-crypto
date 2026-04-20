import { Bench } from "tinybench";
import {
    Ciphersuite,
    ClientId,
    ConversationId,
    Credential,
    CredentialType,
} from "@wireapp/core-crypto/native";
import {
    benchmarkParameters,
    tinybench_setup,
} from "../../shared/benches/utils";
import { ccInit, setup, teardown, DELIVERY_SERVICE } from "../test/utils";

async function run() {
    await setup();
    const parameters = await benchmarkParameters();
    const bench = new Bench({
        name: "Process Messages Benchmark",
        time: 1000,
        iterations: 5,
        warmupIterations: 1,
        setup: tinybench_setup,
        teardown: teardown,
    });

    for (const { count, size, cipherSuite } of parameters) {
        const aliceId = new ClientId(Buffer.from(crypto.randomUUID()).buffer);
        const aliceCc = await ccInit(aliceId);

        const aliceCredential = Credential.basic(cipherSuite, aliceId);

        await aliceCc.transaction(async (ctx) => {
            await ctx.addCredential(aliceCredential);
        });

        const bobId = new ClientId(Buffer.from(crypto.randomUUID()).buffer);
        const bobCc = await ccInit(bobId);

        const bobCredential = Credential.basic(cipherSuite, bobId);

        await bobCc.transaction(async (ctx) => {
            await ctx.addCredential(bobCredential);
        });

        const conversationIdStr = crypto.randomUUID();
        const conversationId = new ConversationId(
            new TextEncoder().encode(conversationIdStr).buffer
        );

        await aliceCc.transaction(async (ctx) => {
            const [credentialRef] = await ctx.getCredentials();
            await ctx.createConversation(conversationId, credentialRef!);
        });

        const kp = await bobCc.transaction(async (ctx) => {
            const [credentialRef] = await ctx.findCredentials({
                ciphersuite: cipherSuite,
                credentialType: CredentialType.Basic,
            });
            return await ctx.generateKeyPackage(credentialRef!);
        });

        await aliceCc.transaction(
            async (ctx) =>
                await ctx.addClientsToConversation(conversationId, [kp])
        );
        const commitBundle = await DELIVERY_SERVICE.getLatestCommitBundle();

        await bobCc.transaction(
            async (ctx) =>
                await ctx.processWelcomeMessage(commitBundle.welcome!)
        );

        const message = new Uint8Array(size);

        // Multiple iterations of a benchmark happen on the same cc instances. This means that we can't encrypt the messages beforehand as this would lead to bob decrypting the same messages over and over again.
        bench.add(
            `cipherSuite=${Ciphersuite[cipherSuite]} size=${size}B count=${count}`,
            async () => {
                const encryptedMessages = await aliceCc.transaction(
                    async (ctx) => {
                        const encryptedMessages: ArrayBuffer[] = [];
                        for (let i = 0; i < count; i++) {
                            const encryptedMessage = await ctx.encryptMessage(
                                conversationId,
                                message.buffer
                            );

                            encryptedMessages.push(encryptedMessage);
                        }
                        return encryptedMessages;
                    }
                );
                const start = bench.now();
                await bobCc.transaction(async (ctx) => {
                    for (const message of encryptedMessages) {
                        await ctx.decryptMessage(conversationId, message);
                    }
                });
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
