import { expect } from "@wdio/globals";
import {
    ALICE_ID,
    BOB_ID,
    ccInit,
    CONV_ID,
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
        await ccInit(ALICE_ID);
        await ccInit(BOB_ID);
        await createConversation(ALICE_ID, CONV_ID);
        const groupInfo = await invite(ALICE_ID, BOB_ID, CONV_ID);
        expect(groupInfo.encryptionType).toBe(
            GroupInfoEncryptionType.Plaintext
        );
        expect(groupInfo.ratchetTreeType).toBe(RatchetTreeType.Full);
    });

    it("should allow sending messages", async () => {
        await ccInit(ALICE_ID);
        await ccInit(BOB_ID);
        await createConversation(ALICE_ID, CONV_ID);
        await invite(ALICE_ID, BOB_ID, CONV_ID);
        const messageText = "Hello world!";
        const [decryptedByAlice, decryptedByBob] = await roundTripMessage(
            ALICE_ID,
            BOB_ID,
            CONV_ID,
            messageText
        );
        expect(decryptedByAlice).toBe(messageText);
        expect(decryptedByBob).toBe(messageText);
    });
});
