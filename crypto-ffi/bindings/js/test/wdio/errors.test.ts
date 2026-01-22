import { browser, expect } from "@wdio/globals";
import { ccInit, createConversation, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { ConversationId, type CommitBundle } from "../../src/CoreCrypto";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("core crypto errors", () => {
    it("should build correctly when constructed by cc", async () => {
        const alice = crypto.randomUUID();
        const convId = crypto.randomUUID();
        await ccInit(alice);
        await createConversation(alice, convId);

        const result = await browser.execute(
            async (clientName, convId) => {
                const cc = window.ensureCcDefined(clientName);

                const conversationIdBuffer = new TextEncoder().encode(
                    convId
                ).buffer;
                const conversationId = new window.ccModule.ConversationId(
                    conversationIdBuffer
                );
                const CoreCryptoError = window.ccModule.CoreCryptoError;
                const MlsError = window.ccModule.MlsError;

                try {
                    await cc.newTransaction(async (cx) => {
                        const [credentialRef] = await cx.getFilteredCredentials(
                            {
                                credentialType:
                                    window.ccModule.CredentialType.Basic,
                            }
                        );
                        await cx.createConversation(
                            conversationId,
                            credentialRef!
                        );
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
                                    new Uint8Array(conversationIdBuffer)
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
            },
            alice,
            convId
        );
        expect(result.errorWasThrown).toBe(true);
        expect(result.isCorrectInstance).toBe(true);
        expect(result.errorConvIdMatches).toBe(true);
    });

    it("should be correct when message rejected", async () => {
        const alice = crypto.randomUUID();
        const convId = crypto.randomUUID();

        browser.execute((_) => {
            const transport_override = {
                async sendCommitBundle(_: CommitBundle) {
                    return { abort: { reason: "just testing" } };
                },
            };

            window.deliveryService = {
                ...window.deliveryService,
                ...transport_override,
            };
        });

        await ccInit(alice);
        await createConversation(alice, convId);

        const result = await browser.execute(
            async (clientName, convId) => {
                const cc = window.ensureCcDefined(clientName);

                window.deliveryService = {
                    ...window.deliveryService,
                    ...{
                        async sendCommitBundle(_: CommitBundle) {
                            return { abort: { reason: "just testing" } };
                        },
                    },
                };

                const conversationId = new window.ccModule.ConversationId(
                    new TextEncoder().encode(convId).buffer
                );
                const CoreCryptoError = window.ccModule.CoreCryptoError;
                const MlsError = window.ccModule.MlsError;
                try {
                    await cc.newTransaction(async (cx) => {
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
            },
            alice,
            convId
        );

        expect(result.errorWasThrown).toBe(true);
        expect(result.errorTypeAndReasonMatch).toBe(true);
    });
});

it("should build correctly when constructed by ubrn", async () => {
    const alice = crypto.randomUUID();
    const convId = crypto.randomUUID();
    await ccInit(alice);
    const result = await browser.execute(
        async (clientName, convId) => {
            const cc = window.ensureCcDefined(clientName);

            try {
                await cc.newTransaction(async (cx) => {
                    // pass in a string argument instead of a `ConversationId` instance
                    const [credentialRef] = await cx.getFilteredCredentials({
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
        },
        alice,
        convId
    );

    expect(result.errorWasThrown).toBe(true);
    expect(result.isCorrectInstance).toBe(true);
    expect(result.message).toBe("Cannot lower this object to a pointer");
});

describe("Error type mapping", () => {
    it("should work for conversation already exists", async () => {
        const alice = crypto.randomUUID();
        const convId = crypto.randomUUID();
        await ccInit(alice);
        await createConversation(alice, convId);

        const isCorrectErrorInstance = await browser.execute(
            async (clientName, conversationId) => {
                const cc = window.ensureCcDefined(clientName);
                const cid = new window.ccModule.ConversationId(
                    new TextEncoder().encode(conversationId).buffer
                );
                try {
                    await cc.newTransaction(async (ctx) => {
                        const [credentialRef] =
                            await ctx.getFilteredCredentials({
                                credentialType:
                                    window.ccModule.CredentialType.Basic,
                            });
                        await ctx.createConversation(cid, credentialRef!);
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
            },
            alice,
            convId
        );

        expect(isCorrectErrorInstance).toBe(true);
    });
});
