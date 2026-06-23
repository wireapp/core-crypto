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
            const cc = await helpers.proteusInit();
            const lastResortPrekeyId = ccModule.proteusLastResortPrekeyId();
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

        expect(result.lastResortPrekeyId).toBe(u16MAX);
        expect(result.lastResortPrekey1).toStrictEqual(
            result.lastResortPrekey2
        );
    });

    it("new session from prekey should succeed", async () => {
        await browser.execute(async () => {
            const sessionId = crypto.randomUUID();
            const alice = await helpers.proteusInit();
            const bob = await helpers.proteusInit();
            await helpers.newProteusSessionFromPrekey(alice, bob, sessionId);
        });
    });

    it("new session from message should succeed", async () => {
        const message = "Hello, world!";
        const decryptedMessage = await browser.execute(async (message) => {
            const sessionId = crypto.randomUUID();
            const alice = await helpers.proteusInit();
            const bob = await helpers.proteusInit();
            // Session for alice
            await helpers.newProteusSessionFromPrekey(alice, bob, sessionId);
            // Session for bob
            return await helpers.newProteusSessionFromMessage(
                alice,
                bob,
                sessionId,
                message
            );
        }, message);
        expect(decryptedMessage).toBe(message);
    });

    it("initializing same session twice should fail", async () => {
        await expect(
            browser.execute(async () => {
                const sessionId = crypto.randomUUID();
                const alice = await helpers.proteusInit();
                const bob = await helpers.proteusInit();
                // Session for alice
                await helpers.newProteusSessionFromPrekey(
                    alice,
                    bob,
                    sessionId
                );
                // Session for bob
                const message = "Hello, world!";
                const decryptedMessage =
                    await helpers.newProteusSessionFromMessage(
                        alice,
                        bob,
                        sessionId,
                        message
                    );

                if (decryptedMessage != message) {
                    throw new Error("Messages should match");
                }
                await helpers.newProteusSessionFromMessage(
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
