import { expect } from "chai";
import { runOnPlatform, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { GroupInfoEncryptionType, RatchetTreeType } from "#core-crypto";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("conversation", () => {
    it("should allow inviting members", async () => {
        const groupInfo = await runOnPlatform(async () => {
            const alice = await helpers.ccInit();
            const bob = await helpers.ccInit();
            const convId = await helpers.createConversation(alice);
            return await helpers.invite(alice, bob, convId);
        });
        expect(groupInfo.encryptionType).to.equal(
            GroupInfoEncryptionType.Plaintext
        );
        expect(groupInfo.ratchetTreeType).to.equal(RatchetTreeType.Full);
    });

    it("should allow sending messages", async () => {
        const messageText = "Hello world!";
        const [decryptedByAlice, decryptedByBob] = await runOnPlatform(
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
        expect(decryptedByAlice).to.equal(messageText);
        expect(decryptedByBob).to.equal(messageText);
    });
});
