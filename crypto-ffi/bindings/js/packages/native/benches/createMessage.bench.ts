import { Bench } from "tinybench";
import { CipherSuite } from "@wireapp/core-crypto/native";
import {
    logResults,
    messageBenchmarkParameters,
    tinybenchSetup,
} from "../../shared/benches/utils";
import { ccInit, createConversation, setup, teardown } from "../test/utils";

async function run() {
    await setup();
    const parameters = await messageBenchmarkParameters();
    const bench = new Bench({
        name: "Create Messages Benchmark",
        time: 1000,
        iterations: 5,
        warmupIterations: 1,
        setup: tinybenchSetup,
        teardown: teardown,
    });

    for (const { count, size, cipherSuite } of parameters) {
        const message = new Uint8Array(size);
        const cc = await ccInit({ withBasicCredential: true, cipherSuite });
        const conversationId = await createConversation(cc);

        bench.add(
            `cipherSuite=${CipherSuite[cipherSuite]} size=${size}B count=${count}`,
            async () => {
                await cc.transaction(async (ctx) => {
                    for (let i = 0; i < count; i++) {
                        await ctx.encryptMessage(conversationId, message);
                    }
                });
            }
        );
    }
    console.log(`Starting ${bench.name}`);
    await bench.run();

    await logResults(bench.name, bench.table());
}

await run();
