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
import { bench, run } from "mitata";
import { afterEach, beforeEach, describe } from "mocha";
import { browser } from "@wdio/globals";

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
 * @param {number} messageCount
 * @return {Promise<number[][]>} A promise resolving to an array of {@link messageCount} arrays, each containing
 * an encrypted message.
 */
async function encrypt(
    clientName: string,
    conversationId: string,
    messageCount: number
): Promise<number[][]> {
    return await browser.execute(
        async (clientName, conversationId, messageCount) => {
            const cc = window.ensureCcDefined(clientName);
            const encoder = new TextEncoder();
            const conversationIdBytes = encoder.encode(conversationId);
            return await cc.transaction(async (ctx) => {
                const encryptedMessages: number[][] = [];
                const messageBytes = await cc.randomBytes(100);
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
        messageCount
    );
}

/**
 * Decrypts a list of previously encrypted messages, using the `clientName` client in the `conversationId` conversation.
 *
 * @param {string} clientName
 * @param {string} conversationId
 * @param {number[][]} encryptedMessages
 * @return {Promise<void>}
 */
async function decrypt(
    clientName: string,
    conversationId: string,
    encryptedMessages: number[][]
): Promise<void> {
    return await browser.execute(
        async (clientName, conversationId, encryptedMessages) => {
            const cc = window.ensureCcDefined(clientName);
            const encoder = new TextEncoder();
            const conversationIdBytes = encoder.encode(conversationId);
            return await cc.transaction(async (ctx) => {
                for (const encryptedMessage of encryptedMessages) {
                    await ctx.decryptMessage(
                        conversationIdBytes,
                        Uint8Array.from(encryptedMessage)
                    );
                }
            });
        },
        clientName,
        conversationId,
        encryptedMessages
    );
}

bench("decrypt 1000 messages", async function* () {
    yield async () => {
        // TODO This should be in "beforeEach", once it is available (https://github.com/evanwashere/mitata/issues/37)
        const messages = await encrypt(ALICE_ID, CONV_ID, 200);
        await decrypt(BOB_ID, CONV_ID, messages);
    };
});

describe("messages", () => {
    it("decrypt 1000 messages", async () => {
        await ccInit(ALICE_ID);
        await ccInit(BOB_ID);
        await createConversation(ALICE_ID, CONV_ID);
        await invite(ALICE_ID, BOB_ID, CONV_ID);
        await run();
    });
});
