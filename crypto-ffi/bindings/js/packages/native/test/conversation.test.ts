import {
    ccInit,
    createConversation,
    invite,
    roundTripMessage,
    setup,
    teardown,
} from "./utils";
import { test, expect, afterEach, beforeEach, describe } from "bun:test";
import {
    GroupInfoEncryptionType,
    RatchetTreeType,
} from "@wireapp/core-crypto/native";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("conversation", () => {
    test("should allow inviting members", async () => {
        const alice = await ccInit();
        const bob = await ccInit();
        const convId = await createConversation(alice);
        const groupInfo = await invite(alice, bob, convId);
        expect(groupInfo.encryptionType).toBe(
            GroupInfoEncryptionType.Plaintext
        );
        expect(groupInfo.ratchetTreeType).toBe(RatchetTreeType.Full);
    });

    test("should allow sending messages", async () => {
        const messageText = "Hello world!";
        const alice = await ccInit();
        const bob = await ccInit();
        const convId = await createConversation(alice);
        await invite(alice, bob, convId);
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
