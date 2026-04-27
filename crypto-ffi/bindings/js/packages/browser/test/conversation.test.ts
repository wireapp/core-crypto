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
            const alice = await window.helpers.ccInit();
            const bob = await window.helpers.ccInit();
            const convId = await window.helpers.createConversation(alice);
            return await window.helpers.invite(alice, bob, convId);
        });
        await expect(groupInfo.encryptionType).toBe(
            GroupInfoEncryptionType.Plaintext
        );
        await expect(groupInfo.ratchetTreeType).toBe(RatchetTreeType.Full);
    });

    it("should allow sending messages", async () => {
        const messageText = "Hello world!";
        const [decryptedByAlice, decryptedByBob] = await browser.execute(
            async (messageText) => {
                const alice = await window.helpers.ccInit();
                const bob = await window.helpers.ccInit();
                const convId = await window.helpers.createConversation(alice);
                await window.helpers.invite(alice, bob, convId);
                return await window.helpers.roundTripMessage(
                    alice,
                    bob,
                    convId,
                    messageText
                );
            },
            messageText
        );
        await expect(decryptedByAlice).toBe(messageText);
        await expect(decryptedByBob).toBe(messageText);
    });
});
