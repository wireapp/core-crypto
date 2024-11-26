import {
    ALICE_ID,
    BOB_ID,
    ccInit,
    CONV_ID,
    createConversation,
    invite,
    setup,
    teardown,
} from "../test/utils";
import { afterEach, beforeEach, describe } from "mocha";
import { browser, expect } from "@wdio/globals";
import { writeFile } from "fs/promises";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

/**
 * Encrypts {@link messageCount} many messages using the `clientName` client in the `conversationId` conversation.
 *
 * @param {string} clientName
 * @param {string} conversationId
 * @param message
 * @param {number} messageCount
 * @return {Promise<number[][]>} A promise resolving to an array of {@link messageCount} arrays, each containing
 * an encrypted message.
 */
async function encrypt(
    clientName: string,
    conversationId: string,
    message: string,
    messageCount: number
): Promise<number[][]> {
    return await browser.execute(
        async (clientName, conversationId, message, messageCount) => {
            const cc = window.ensureCcDefined(clientName);
            const encoder = new TextEncoder();
            const conversationIdBytes = encoder.encode(conversationId);
            return await cc.transaction(async (ctx) => {
                const encryptedMessages: number[][] = [];
                const messageBytes = encoder.encode(message);
                for (let i = 0; i < messageCount; i++) {
                    const encryptedMessage = await ctx.encryptMessage(
                        conversationIdBytes,
                        messageBytes
                    );

                    encryptedMessages.push(Array.from(encryptedMessage));
                }
                return encryptedMessages;
            });
        },
        clientName,
        conversationId,
        message,
        messageCount
    );
}

/**
 * Decrypts a list of previously encrypted messages, using the `clientName` client in the `conversationId` conversation.
 *
 * @param {string} clientName
 * @param {string} conversationId
 * @param {number[][]} encryptedMessages
 * @return {Promise<{ decryptedMessages: number[][]; durationMilliSeconds: number }>} The decrypted message bytes and
 * the duration of the operation in milliseconds
 */
async function decrypt(
    clientName: string,
    conversationId: string,
    encryptedMessages: number[][]
): Promise<{ decryptedMessages: number[][]; durationMilliSeconds: number }> {
    return await browser.execute(
        async (clientName, conversationId, encryptedMessages) => {
            const cc = window.ensureCcDefined(clientName);
            const encoder = new TextEncoder();
            const conversationIdBytes = encoder.encode(conversationId);
            return await cc.transaction(async (ctx) => {
                const start = performance.now();

                const decryptedMessages = await Promise.all(
                    encryptedMessages.map(
                        async (encryptedMessage) =>
                            (
                                await ctx.decryptMessage(
                                    conversationIdBytes,
                                    Uint8Array.from(encryptedMessage)
                                )
                            ).message
                    )
                );

                const end = performance.now();
                const duration = end - start;

                return {
                    decryptedMessages: decryptedMessages
                        .filter(
                            (message): message is Uint8Array =>
                                message !== undefined
                        )
                        .map((message) => Array.from(message)),
                    durationMilliSeconds: duration,
                };
            });
        },
        clientName,
        conversationId,
        encryptedMessages
    );
}

describe("messages", () => {
    const MESSAGE_COUNT = 1000;
    it(`decrypt ${MESSAGE_COUNT} messages`, async () => {
        await ccInit(ALICE_ID);
        await ccInit(BOB_ID);
        await createConversation(ALICE_ID, CONV_ID);
        await invite(ALICE_ID, BOB_ID, CONV_ID);

        const MESSAGE = "Hello world!";
        const messages = await encrypt(
            ALICE_ID,
            CONV_ID,
            MESSAGE,
            MESSAGE_COUNT
        );
        const { decryptedMessages, durationMilliSeconds: duration } =
            await decrypt(BOB_ID, CONV_ID, messages);
        expect(decryptedMessages.length).toBe(MESSAGE_COUNT);
        const decoder = new TextDecoder();
        const decodedMessages = decryptedMessages.map((encodedMessage) =>
            decoder.decode(new Uint8Array(encodedMessage))
        );
        expect(decodedMessages).toStrictEqual(
            Array(MESSAGE_COUNT).fill(MESSAGE)
        );

        console.log(`Decrypted ${MESSAGE_COUNT} messages in ${duration} ms`);

        if (!process.env.CI) return;
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
