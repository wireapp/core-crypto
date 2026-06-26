import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import {
    ConversationId,
    type CommitBundle,
} from "@wireapp/core-crypto/browser";

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
        const result = await browser.execute(async () => {
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
                return {
                    errorWasThrown: false,
                };
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
                        errorWasThrown: true,
                        isCorrectInstance: true,
                        errorConvIdMatches:
                            JSON.stringify(conversationIdFromError) ===
                            JSON.stringify(
                                new Uint8Array(conversationId.copyBytes())
                            ),
                    };
                } else {
                    return {
                        errorWasThrown: true,
                        isCorrectInstance: false,
                        errorConvIdMatches: false,
                    };
                }
            }
        });
        expect(result.errorWasThrown).toBe(true);
        expect(result.isCorrectInstance).toBe(true);
        expect(result.errorConvIdMatches).toBe(true);
    });

    it("should be correct when message rejected", async () => {
        const result = await browser.execute(async () => {
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
                return {
                    errorWasThrown: false,
                };
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
        });

        expect(result.errorWasThrown).toBe(true);
        expect(result.errorTypeAndReasonMatch).toBe(true);
    });
});

it("should build correctly when constructed by ubrn", async () => {
    const convId = crypto.randomUUID();
    const result = await browser.execute(async (convId) => {
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
            return {
                errorWasThrown: false,
            };
        } catch (err) {
            return {
                errorWasThrown: true,
                isCorrectInstance: Error.isError(err),
                message: Error.isError(err) && err.message,
            };
        }
    }, convId);

    expect(result.errorWasThrown).toBe(true);
    expect(result.isCorrectInstance).toBe(true);
    expect(result.message).toBe("Cannot lower this object to a pointer");
});

describe("Error type mapping", () => {
    it("should work for conversation already exists", async () => {
        const isCorrectErrorInstance = await browser.execute(async () => {
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
            return false;
        });

        expect(isCorrectErrorInstance).toBe(true);
    });
});
