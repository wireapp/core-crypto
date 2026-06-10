import {
    CoreCryptoError,
    proteusLastResortPrekeyId,
} from "@wireapp/core-crypto/native";
import {
    newProteusSessionFromMessage,
    newProteusSessionFromPrekey,
    proteusInit,
    setup,
    teardown,
} from "./utils";
import { test, expect, afterEach, beforeEach, describe } from "bun:test";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("proteus", () => {
    test("should initialize correctly", async () => {
        const cc = await proteusInit();
        const lastResortPrekeyId = proteusLastResortPrekeyId();
        const [prekey1, prekey2] = await cc.transaction(async (ctx) => {
            const prekey1 = await ctx.proteusLastResortPrekey();
            const prekey2 = await ctx.proteusLastResortPrekey();
            return [prekey1, prekey2];
        });

        const u16MAX = Math.pow(2, 16) - 1;

        expect(lastResortPrekeyId).toBe(u16MAX);
        expect(prekey1).toStrictEqual(prekey2);
    });

    test("new session from prekey should succeed", async () => {
        const sessionId = crypto.randomUUID();
        const alice = await proteusInit();
        const bob = await proteusInit();
        await newProteusSessionFromPrekey(alice, bob, sessionId);
    });

    test("new session from message should succeed", async () => {
        const message = "Hello, world!";
        const sessionId = crypto.randomUUID();
        const alice = await proteusInit();
        const bob = await proteusInit();
        // Session for alice
        await newProteusSessionFromPrekey(alice, bob, sessionId);
        // Session for bob
        const decryptedMessage = await newProteusSessionFromMessage(
            alice,
            bob,
            sessionId,
            message
        );
        expect(decryptedMessage).toBe(message);
    });

    test("initializing same session twice should fail", async () => {
        const sessionId = crypto.randomUUID();
        const alice = await proteusInit();
        const bob = await proteusInit();
        // Session for alice
        await newProteusSessionFromPrekey(alice, bob, sessionId);

        // Session for bob
        const message = "Hello, world!";
        const decryptedMessage = await newProteusSessionFromMessage(
            alice,
            bob,
            sessionId,
            message
        );

        expect(decryptedMessage).toEqual(message);

        try {
            await newProteusSessionFromMessage(alice, bob, sessionId, message);
            throw new Error("Expected newProteusSessionFromMessage to reject");
        } catch (err) {
            expect(CoreCryptoError.Proteus.instanceOf(err)).toBeTrue();
        }
    });
});
