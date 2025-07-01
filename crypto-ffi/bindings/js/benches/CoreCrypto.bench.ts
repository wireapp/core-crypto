import {
    ALICE_ID,
    BOB_ID,
    ccInit,
    CONV_ID,
    createConversation,
    invite,
    setup,
    teardown,
} from "../test/wdio/utils";
import { afterEach, beforeEach, describe } from "mocha";
import { browser, expect } from "@wdio/globals";
import { writeFile } from "fs/promises";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

async function measureDecryption(
    client1: string,
    client2: string,
    conversationId: string,
    message: string,
    messageCount: number
) {
    const cc1 = window.ensureCcDefined(client1);
    const encoder = new TextEncoder();
    const cid = new window.ccModule.ConversationId(encoder.encode(conversationId))
    const messageBytes = encoder.encode(message);

    const encryptedMessages = await cc1.transaction(async (ctx) => {
        const encryptedMessages = [];
        for (let i = 0; i < messageCount; i++) {
            const encryptedMessage = await ctx.encryptMessage(
                cid,
                messageBytes
            );

            encryptedMessages.push(encryptedMessage);
        }
        return encryptedMessages;
    });

    // measure decryption performance
    const cc2 = window.ensureCcDefined(client2);
    return await cc2.transaction(async (ctx) => {
        const start = performance.now();

        const decryptedMessages: (Uint8Array | undefined)[] = [];
        for (const encryptedMessage of encryptedMessages) {
            const decrypted = await ctx.decryptMessage(
                cid,
                encryptedMessage
            );
            decryptedMessages.push(decrypted.message);
        }
        const end = performance.now();
        const duration = end - start;
        const decryptedTextMessages = decryptedMessages
            .filter((message): message is Uint8Array => message !== undefined)
            .map((x) => String.fromCharCode(...x));
        return {
            decryptedMessages: decryptedTextMessages,
            durationMilliSeconds: duration,
        };
    });
}

describe("messages", () => {
    const MESSAGE_COUNT = 1000;
    it(`decrypt ${MESSAGE_COUNT} messages`, async () => {
        await ccInit(ALICE_ID);
        await ccInit(BOB_ID);
        await createConversation(ALICE_ID, CONV_ID);
        await invite(ALICE_ID, BOB_ID, CONV_ID);

        const MESSAGE = "Hello world!";
        const { decryptedMessages, durationMilliSeconds: duration } =
            await browser.execute(
                measureDecryption,
                ALICE_ID,
                BOB_ID,
                CONV_ID,
                MESSAGE,
                MESSAGE_COUNT
            );

        expect(decryptedMessages.length).toBe(MESSAGE_COUNT);
        expect(decryptedMessages).toStrictEqual(
            Array(MESSAGE_COUNT).fill(MESSAGE)
        );

        console.log(`Decrypted ${MESSAGE_COUNT} messages in ${duration} ms`);

        if (!process.env["CI"]) return;

        // This format can directly be used by bencher
        const bencherJson = {
            [`decrypt${MESSAGE_COUNT}MessagesWeb`]: {
                latency: {
                    // convert ms to ns, the unit bencher expects
                    value: duration * 1e6,
                },
            },
        };

        await writeFile(
            `web_benchmark_results.json`,
            JSON.stringify(bencherJson, null, 2)
        );
    });
});
