import {
    ccInit,
    createConversation,
    setup,
    teardown,
    TestDeliveryService,
} from "./utils";
import { test, expect, afterEach, beforeEach, describe } from "bun:test";
import {
    cipherSuiteDefault,
    CommitBundle,
    ConversationId,
    CoreCryptoError,
    CredentialType,
    MlsError,
    MlsTransportError,
} from "@wireapp/core-crypto/native";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

/*
 * Most if not all tests in this module violate the "don't test the library" principle. However, they're also showing
 * how to access the errors we're throwing, which isn't trivial (for someone unfamiliar with TS typeguards).
 * If the access pattern changes, we want to notice so that we can document the migration for library consumers.
 */

describe("core crypto errors", () => {
    test("should build correctly when constructed by cc", async () => {
        const cc = await ccInit();

        const conversationId = await createConversation(cc);

        try {
            const [credentialRef] = await cc.findCredentials({
                credentialType: CredentialType.Basic,
            });
            await cc.transaction(async (cx) => {
                await cx.createConversation(conversationId, credentialRef!);
            });

            throw new Error("Expected createConversation to reject");
        } catch (err) {
            expect(CoreCryptoError.Mls.instanceOf(err)).toBeTrue();
            if (!CoreCryptoError.Mls.instanceOf(err)) {
                throw new Error("expected CoreCryptoError.Mls", { cause: err });
            }
            expect(
                MlsError.ConversationAlreadyExists.instanceOf(
                    err.inner.mlsError
                )
            ).toBeTrue();
            if (
                !MlsError.ConversationAlreadyExists.instanceOf(
                    err.inner.mlsError
                )
            ) {
                throw new Error("Expected Mls.ConversationAlreadyExists", {
                    cause: err,
                });
            }
            expect(err.inner.mlsError.inner.conversationId).toEqual(
                conversationId.copyBytes()
            );
        }
    });

    test("should be correct when message rejected", async () => {
        class TestDeliveryServiceOverride extends TestDeliveryService {
            async sendCommitBundle(_: CommitBundle) {
                throw MlsTransportError.MessageRejected.new({
                    reason: "just testing",
                });
            }
        }

        const cc = await ccInit({
            withBasicCredential: true,
            cipherSuite: cipherSuiteDefault(),
            deliveryService: new TestDeliveryServiceOverride(),
        });
        const conversationId = await createConversation(cc);

        try {
            await cc.transaction(async (cx) => {
                await cx.updateKeyingMaterial(conversationId);
            });
            throw new Error("Expected updateKeyingMaterial to reject");
        } catch (err) {
            expect(CoreCryptoError.Mls.instanceOf(err)).toBeTrue();
            if (!CoreCryptoError.Mls.instanceOf(err)) {
                throw new Error("expected CoreCryptoError.Mls", { cause: err });
            }
            expect(MlsError.MessageRejected.instanceOf(err.inner.mlsError));
            if (!MlsError.MessageRejected.instanceOf(err.inner.mlsError)) {
                throw new Error("expected MlsError.MessageRejected", {
                    cause: err,
                });
            }
            expect(err.inner.mlsError.inner.reason).toBe("just testing");
        }
    });

    test("should build correctly when constructed by ubrn", async () => {
        const convId = crypto.randomUUID();
        const cc = await ccInit();

        expect(
            cc.transaction(async (cx) => {
                // pass in a string argument instead of a `ConversationId` instance
                const [credentialRef] = await cc.findCredentials({
                    credentialType: CredentialType.Basic,
                });
                await cx.createConversation(
                    convId as unknown as ConversationId,
                    credentialRef!
                );
            })
        ).rejects.toThrow("Cannot lower this object to a pointer");
    });

    describe("Error type mapping", () => {
        test("should work for conversation already exists", async () => {
            const cc = await ccInit();
            const conversationId = await createConversation(cc);

            try {
                const [credentialRef] = await cc.findCredentials({
                    credentialType: CredentialType.Basic,
                });
                await cc.transaction(async (ctx) => {
                    await ctx.createConversation(
                        conversationId,
                        credentialRef!
                    );
                });
                throw new Error("Expected createConversation to reject");
            } catch (e) {
                expect(CoreCryptoError.Mls.instanceOf(e)).toBeTrue();
                if (!CoreCryptoError.Mls.instanceOf(e)) {
                    throw new Error("expected CoreCryptoError.Mls", {
                        cause: e,
                    });
                }
                expect(
                    MlsError.ConversationAlreadyExists.instanceOf(
                        e.inner.mlsError
                    )
                ).toBeTrue();
                if (
                    !MlsError.ConversationAlreadyExists.instanceOf(
                        e.inner.mlsError
                    )
                ) {
                    throw new Error(
                        "expected MlsError.ConversationAlreadyExists",
                        { cause: e }
                    );
                }
                expect(e.inner.mlsError.inner.conversationId).toBeDefined();
            }
        });
    });
});
