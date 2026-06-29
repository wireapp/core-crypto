import { runOnPlatform, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { ConversationId, type CommitBundle } from "#core-crypto";
import { expect } from "chai";

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
    it("should build correctly when constructed by cc", async () => {
        const result = await runOnPlatform(async () => {
            const cc = await helpers.ccInit();

            const conversationId = await helpers.createConversation(cc);
            const CoreCryptoError = ccModule.CoreCryptoError;
            const MlsError = ccModule.MlsError;

            try {
                const [credentialRef] = await cc.findCredentials({
                    credentialType: ccModule.CredentialType.Basic,
                });
                await cc.transaction(async (cx) => {
                    await cx.createConversation(conversationId, credentialRef!);
                });
            } catch (err) {
                if (
                    CoreCryptoError.Mls.instanceOf(err) &&
                    MlsError.ConversationAlreadyExists.instanceOf(
                        err.inner.mlsError
                    )
                ) {
                    const conversationIdFromError = new Uint8Array(
                        err.inner.mlsError.inner.conversationId
                    );
                    return {
                        isCorrectInstance: true,
                        errorConvIdMatches:
                            JSON.stringify(conversationIdFromError) ===
                            JSON.stringify(
                                new Uint8Array(conversationId.copyBytes())
                            ),
                    };
                }
            }
            throw new Error("Expected ConversationAlreadyExists error");
        });
        expect(result.isCorrectInstance).to.equal(true);
        expect(result.errorConvIdMatches).to.equal(true);
    });

    it("should be correct when message rejected", async () => {
        const result = await runOnPlatform(async () => {
            const transport_override = {
                async sendCommitBundle(_: CommitBundle) {
                    throw ccModule.MlsTransportError.MessageRejected.new({
                        reason: "just testing",
                    });
                },
            };

            deliveryService = {
                ...deliveryService,
                ...transport_override,
            };

            const cc = await helpers.ccInit();
            const conversationId = await helpers.createConversation(cc);

            const CoreCryptoError = ccModule.CoreCryptoError;
            const MlsError = ccModule.MlsError;
            try {
                await cc.transaction(async (cx) => {
                    await cx.updateKeyingMaterial(conversationId);
                });
            } catch (err) {
                return CoreCryptoError.Mls.instanceOf(err) &&
                    MlsError.MessageRejected.instanceOf(err.inner.mlsError)
                    ? {
                          errorWasThrown: true,
                          errorTypeAndReasonMatch:
                              "just testing" ===
                              err.inner.mlsError.inner.reason,
                      }
                    : {
                          errorWasThrown: true,
                          errorTypeAndReasonMatch: false,
                      };
            }
            throw new Error("Expected MlsError.MessageRejected");
        });

        expect(result.errorWasThrown).to.equal(true);
        expect(result.errorTypeAndReasonMatch).to.equal(true);
    });
});

it("should build correctly when constructed by ubrn", async () => {
    const convId = crypto.randomUUID();
    const result = await runOnPlatform(async (convId) => {
        const cc = await helpers.ccInit();

        try {
            await cc.transaction(async (cx) => {
                // pass in a string argument instead of a `ConversationId` instance
                const [credentialRef] = await cc.findCredentials({
                    credentialType: ccModule.CredentialType.Basic,
                });
                await cx.createConversation(
                    convId as unknown as ConversationId,
                    credentialRef!
                );
            });
        } catch (err) {
            return {
                message: Error.isError(err) && err.message,
            };
        }
        throw Error("Expected Ubrn lowering error");
    }, convId);

    expect(result.message).to.equal("Cannot lower this object to a pointer");
});

describe("Error type mapping", () => {
    it("should work for conversation already exists", async () => {
        const isCorrectErrorInstance = await runOnPlatform(async () => {
            const cc = await helpers.ccInit();
            const conversationId = await helpers.createConversation(cc);

            try {
                const [credentialRef] = await cc.findCredentials({
                    credentialType: ccModule.CredentialType.Basic,
                });
                await cc.transaction(async (ctx) => {
                    await ctx.createConversation(
                        conversationId,
                        credentialRef!
                    );
                });
            } catch (e) {
                return (
                    ccModule.CoreCryptoError.Mls.hasInner(e) &&
                    ccModule.MlsError.ConversationAlreadyExists.instanceOf(
                        e.inner.mlsError
                    ) &&
                    e.inner.mlsError.inner.conversationId !== undefined
                );
            }
            throw new Error("Expected MlsError.ConversationAlreadyExists");
        });

        expect(isCorrectErrorInstance).to.equal(true);
    });
});
