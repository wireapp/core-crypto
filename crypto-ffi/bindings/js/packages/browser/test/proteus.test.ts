import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("proteus", () => {
    it("should initialize correctly", async () => {
        const result = await browser.execute(async () => {
            const cc = await window.helpers.proteusInit();
            const lastResortPrekeyId =
                window.ccModule.proteusLastResortPrekeyId();
            const [prekey1, prekey2] = await cc.transaction(async (ctx) => {
                const prekey1 = await ctx.proteusLastResortPrekey();
                const prekey2 = await ctx.proteusLastResortPrekey();
                return [prekey1, prekey2];
            });

            return {
                lastResortPrekeyId: lastResortPrekeyId,
                lastResortPrekey1: new Uint8Array(prekey1),
                lastResortPrekey2: new Uint8Array(prekey2),
            };
        });

        const u16MAX = Math.pow(2, 16) - 1;

        await expect(result.lastResortPrekeyId).toBe(u16MAX);
        await expect(result.lastResortPrekey1).toStrictEqual(
            result.lastResortPrekey2
        );
    });

    it("new session from prekey should succeed", async () => {
        await browser.execute(async () => {
            const sessionId = window.crypto.randomUUID();
            const alice = await window.helpers.proteusInit();
            const bob = await window.helpers.proteusInit();
            await window.helpers.newProteusSessionFromPrekey(
                alice,
                bob,
                sessionId
            );
        });
    });

    it("new session from message should succeed", async () => {
        const message = "Hello, world!";
        const decryptedMessage = await browser.execute(async (message) => {
            const sessionId = window.crypto.randomUUID();
            const alice = await window.helpers.proteusInit();
            const bob = await window.helpers.proteusInit();
            // Session for alice
            await window.helpers.newProteusSessionFromPrekey(
                alice,
                bob,
                sessionId
            );
            // Session for bob
            return await window.helpers.newProteusSessionFromMessage(
                alice,
                bob,
                sessionId,
                message
            );
        }, message);
        await expect(decryptedMessage).toBe(message);
    });

    it("initializing same session twice should fail", async () => {
        await expect(
            browser.execute(async () => {
                const sessionId = crypto.randomUUID();
                const alice = await window.helpers.proteusInit();
                const bob = await window.helpers.proteusInit();
                // Session for alice
                await window.helpers.newProteusSessionFromPrekey(
                    alice,
                    bob,
                    sessionId
                );
                // Session for bob
                const message = "Hello, world!";
                const decryptedMessage =
                    await window.helpers.newProteusSessionFromMessage(
                        alice,
                        bob,
                        sessionId,
                        message
                    );

                if (decryptedMessage != message) {
                    throw new Error("Messages should match");
                }
                await window.helpers.newProteusSessionFromMessage(
                    alice,
                    bob,
                    sessionId,
                    message
                );
            })
        ).rejects.toThrow(
            // wdio wraps the error and prepends the original message with
            // the error type as prefix
            new Error("Error: CoreCryptoError.Proteus")
        );
    });
});
