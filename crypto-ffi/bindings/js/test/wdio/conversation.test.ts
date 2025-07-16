import { expect } from "@wdio/globals";
import {
    ccInit,
    createConversation,
    invite,
    roundTripMessage,
    setup,
    teardown,
} from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { GroupInfoEncryptionType, RatchetTreeType } from "../../src/CoreCrypto";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("conversation", () => {
    it("should allow inviting members", async () => {
        const alice = crypto.randomUUID();
        const bob = crypto.randomUUID();
        const convId = crypto.randomUUID();
        await ccInit(alice);
        await ccInit(bob);
        await createConversation(alice, convId);
        const groupInfo = await invite(alice, bob, convId);
        expect(groupInfo.encryptionType).toBe(
            GroupInfoEncryptionType.Plaintext
        );
        expect(groupInfo.ratchetTreeType).toBe(RatchetTreeType.Full);
    });

    it("should allow sending messages", async () => {
        const alice = crypto.randomUUID();
        const bob = crypto.randomUUID();
        const convId = crypto.randomUUID();
        await ccInit(alice);
        await ccInit(bob);
        await createConversation(alice, convId);
        await invite(alice, bob, convId);
        const messageText = "Hello world!";
        const [decryptedByAlice, decryptedByBob] = await roundTripMessage(
            alice,
            bob,
            convId,
            messageText
        );
        expect(decryptedByAlice).toBe(messageText);
        expect(decryptedByBob).toBe(messageText);
    });
});
