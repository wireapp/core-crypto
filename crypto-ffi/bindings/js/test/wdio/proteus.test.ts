import { browser, expect } from "@wdio/globals";
import {
    newProteusSessionFromMessage,
    newProteusSessionFromPrekey,
    proteusInit,
    setup,
    teardown,
} from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("proteus", () => {
    it("should initialize correctly", async () => {
        const alice = crypto.randomUUID();
        await proteusInit(alice);
        const result = await browser.execute(async (clientName) => {
            const cc = window.ensureCcDefined(clientName);
            const lastResortPrekeyId =
                window.ccModule.CoreCrypto.proteusLastResortPrekeyId();
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
        }, alice);

        const u16MAX = Math.pow(2, 16) - 1;

        expect(result.lastResortPrekeyId).toBe(u16MAX);
        expect(result.lastResortPrekey1).toStrictEqual(
            result.lastResortPrekey2
        );
    });

    it("new session from prekey should succeed", async () => {
        const alice = crypto.randomUUID();
        const bob = crypto.randomUUID();
        const sessionId = crypto.randomUUID();
        await proteusInit(alice);
        await proteusInit(bob);
        await newProteusSessionFromPrekey(alice, bob, sessionId);
    });

    it("new session from message should succeed", async () => {
        const alice = crypto.randomUUID();
        const bob = crypto.randomUUID();
        const sessionId = crypto.randomUUID();
        await proteusInit(alice);
        await proteusInit(bob);
        // Session for alice
        await newProteusSessionFromPrekey(alice, bob, sessionId);
        const message = "Hello, world!";
        // Session for bob
        const decryptedMessage = await newProteusSessionFromMessage(
            alice,
            bob,
            sessionId,
            message
        );
        expect(decryptedMessage).toBe(message);
    });

    it("initializing same session twice should fail", async () => {
        const alice = crypto.randomUUID();
        const bob = crypto.randomUUID();
        const sessionId = crypto.randomUUID();
        await proteusInit(alice);
        await proteusInit(bob);
        // Session for alice
        await newProteusSessionFromPrekey(alice, bob, sessionId);
        const message = "Hello, world!";
        // Session for bob
        const decryptedMessage = await newProteusSessionFromMessage(
            alice,
            bob,
            sessionId,
            message
        );
        expect(decryptedMessage).toBe(message);

        await expect(
            newProteusSessionFromMessage(alice, bob, sessionId, message)
        ).rejects.toThrow(
            // wdio wraps the error and prepends the original message with
            // the error type as prefix
            new Error("Error: ProteusError.Other")
        );
    });
});
