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
            const cc = await window.helpers.ccInit();

            const conversationId = await window.helpers.createConversation(cc);
            const CoreCryptoError = window.ccModule.CoreCryptoError;
            const MlsError = window.ccModule.MlsError;

            try {
                await cc.transaction(async (cx) => {
                    const [credentialRef] = await cx.findCredentials({
                        credentialType: window.ccModule.CredentialType.Basic,
                    });
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
        await expect(result.errorWasThrown).toBe(true);
        await expect(result.isCorrectInstance).toBe(true);
        await expect(result.errorConvIdMatches).toBe(true);
    });

    it("should be correct when message rejected", async () => {
        const result = await browser.execute(async () => {
            const transport_override = {
                async sendCommitBundle(_: CommitBundle) {
                    throw window.ccModule.MlsTransportError.MessageRejected.new(
                        { reason: "just testing" }
                    );
                },
            };

            window.deliveryService = {
                ...window.deliveryService,
                ...transport_override,
            };

            const cc = await window.helpers.ccInit();
            const conversationId = await window.helpers.createConversation(cc);

            const CoreCryptoError = window.ccModule.CoreCryptoError;
            const MlsError = window.ccModule.MlsError;
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

        await expect(result.errorWasThrown).toBe(true);
        await expect(result.errorTypeAndReasonMatch).toBe(true);
    });
});

it("should build correctly when constructed by ubrn", async () => {
    const convId = crypto.randomUUID();
    const result = await browser.execute(async (convId) => {
        const cc = await window.helpers.ccInit();

        try {
            await cc.transaction(async (cx) => {
                // pass in a string argument instead of a `ConversationId` instance
                const [credentialRef] = await cx.findCredentials({
                    credentialType: window.ccModule.CredentialType.Basic,
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

    await expect(result.errorWasThrown).toBe(true);
    await expect(result.isCorrectInstance).toBe(true);
    await expect(result.message).toBe("Cannot lower this object to a pointer");
});

describe("Error type mapping", () => {
    it("should work for conversation already exists", async () => {
        const isCorrectErrorInstance = await browser.execute(async () => {
            const cc = await window.helpers.ccInit();
            const conversationId = await window.helpers.createConversation(cc);

            try {
                await cc.transaction(async (ctx) => {
                    const [credentialRef] = await ctx.findCredentials({
                        credentialType: window.ccModule.CredentialType.Basic,
                    });
                    await ctx.createConversation(
                        conversationId,
                        credentialRef!
                    );
                });
            } catch (e) {
                return (
                    window.ccModule.CoreCryptoError.Mls.hasInner(e) &&
                    window.ccModule.MlsError.ConversationAlreadyExists.instanceOf(
                        e.inner.mlsError
                    ) &&
                    e.inner.mlsError.inner.conversationId !== undefined
                );
            }
            return false;
        });

        await expect(isCorrectErrorInstance).toBe(true);
    });
});
