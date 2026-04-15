import { Bench } from "tinybench";
import {
    Ciphersuite,
    ClientId,
    ConversationId,
    Credential,
} from "@wireapp/core-crypto/native";
import {
    benchmarkParameters,
    tinybench_setup,
} from "../../shared/benches/utils";
import { ccInit, setup, teardown } from "../test/utils";

async function run() {
    await setup();
    const parameters = await benchmarkParameters();
    const bench = new Bench({
        name: "Create Messages Benchmark",
        time: 1000,
        iterations: 5,
        warmupIterations: 1,
        setup: tinybench_setup,
        teardown: teardown,
    });

    for (const { count, size, cipherSuite } of parameters) {
        const message = new Uint8Array(size);
        const clientId = new ClientId(Buffer.from(crypto.randomUUID()).buffer);
        const cc = await ccInit(clientId);
        const conversationIdStr = crypto.randomUUID();
        const conversationId = new ConversationId(
            new TextEncoder().encode(conversationIdStr).buffer
        );

        const credential = Credential.basic(cipherSuite, clientId);

        await cc.transaction(async (ctx) => {
            await ctx.addCredential(credential);
        });

        await cc.transaction(async (ctx) => {
            const [credentialRef] = await ctx.getCredentials();
            await ctx.createConversation(conversationId, credentialRef!);
        });

        bench.add(
            `cipherSuite=${Ciphersuite[cipherSuite]} size=${size}B count=${count}`,
            async () => {
                await cc.transaction(async (ctx) => {
                    for (let i = 0; i < count; i++) {
                        await ctx.encryptMessage(
                            conversationId,
                            message.buffer
                        );
                    }
                });
            }
        );
    }
    console.log(`Starting ${bench.name}`);
    await bench.run();

    console.log(bench.name);
    console.table(bench.table());
}

await run();
