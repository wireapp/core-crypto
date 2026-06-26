import { expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import {
    GroupInfoEncryptionType,
    RatchetTreeType,
} from "@wireapp/core-crypto/browser";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("conversation", () => {
    it("should allow inviting members", async () => {
        const groupInfo = await browser.execute(async () => {
            const alice = await helpers.ccInit();
            const bob = await helpers.ccInit();
            const convId = await helpers.createConversation(alice);
            return await helpers.invite(alice, bob, convId);
        });
        expect(groupInfo.encryptionType).toBe(
            GroupInfoEncryptionType.Plaintext
        );
        expect(groupInfo.ratchetTreeType).toBe(RatchetTreeType.Full);
    });

    it("should allow sending messages", async () => {
        const messageText = "Hello world!";
        const [decryptedByAlice, decryptedByBob] = await browser.execute(
            async (messageText) => {
                const alice = await helpers.ccInit();
                const bob = await helpers.ccInit();
                const convId = await helpers.createConversation(alice);
                await helpers.invite(alice, bob, convId);
                return await helpers.roundTripMessage(
                    alice,
                    bob,
                    convId,
                    messageText
                );
            },
            messageText
        );
        expect(decryptedByAlice).toBe(messageText);
        expect(decryptedByBob).toBe(messageText);
    });
});
