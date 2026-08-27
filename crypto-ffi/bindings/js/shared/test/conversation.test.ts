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

    it("should allow decrypting targeted messages", async () => {
        const results = await runOnPlatform(async () => {
            const alice = await helpers.ccInit();
            const bobId = helpers.newClientId();
            const bob = await helpers.ccInit({ clientId: bobId });
            const conversationId = await helpers.createConversation(alice);
            await helpers.invite(alice, bob, conversationId);

            const persistedMessage = new TextEncoder().encode(
                "This persisted message targets Bob"
            );
            const persistedCiphertext = await alice.transaction((ctx) =>
                ctx.encryptTargetedMessage(
                    conversationId,
                    bobId,
                    ccModule.TargetedMessagePolicy.Persisted,
                    persistedMessage
                )
            );
            const persistedDecrypted = await bob.transaction((ctx) =>
                ctx.decryptMessage(conversationId, persistedCiphertext)
            );

            const transientMessage = new TextEncoder().encode(
                "This transient message targets Bob"
            );
            const transientCiphertext = await alice.transaction((ctx) =>
                ctx.encryptTargetedMessage(
                    conversationId,
                    bobId,
                    ccModule.TargetedMessagePolicy.Transient,
                    transientMessage
                )
            );
            const transientDecrypted = await bob.transaction((ctx) =>
                ctx.decryptMessage(conversationId, transientCiphertext)
            );

            const decoder = new TextDecoder();

            return {
                persistedMessage: decoder.decode(persistedMessage),
                persistedPlaintext:
                    ccModule.DecryptedMessage.PersistedTargeted.instanceOf(
                        persistedDecrypted
                    )
                        ? decoder.decode(persistedDecrypted.inner.plaintext)
                        : "wrong decrypted variant",
                transientMessage: decoder.decode(transientMessage),
                transientPlaintext:
                    ccModule.DecryptedMessage.TransientTargeted.instanceOf(
                        transientDecrypted
                    )
                        ? decoder.decode(transientDecrypted.inner.plaintext)
                        : "wrong decrypted variant",
            };
        });

        expect(results.persistedPlaintext).to.equal(results.persistedMessage);
        expect(results.transientPlaintext).to.equal(results.transientMessage);
    });

    it("should allow decrypting transient messages", async () => {
        const results = await runOnPlatform(async () => {
            const alice = await helpers.ccInit();
            const bob = await helpers.ccInit();
            const conversationId = await helpers.createConversation(alice);
            await helpers.invite(alice, bob, conversationId);

            const message = new TextEncoder().encode(
                "This is a transient message"
            );
            const ciphertext = await alice.transaction((ctx) =>
                ctx.encryptTransientMessage(conversationId, message)
            );
            const decrypted = await bob.transaction((ctx) =>
                ctx.decryptMessage(conversationId, ciphertext)
            );

            const decoder = new TextDecoder();

            return {
                message: decoder.decode(message),
                plaintext: ccModule.DecryptedMessage.Transient.instanceOf(
                    decrypted
                )
                    ? decoder.decode(decrypted.inner.plaintext)
                    : "wrong decrypted variant",
            };
        });

        expect(results.plaintext).to.equal(results.message);
    });
});
