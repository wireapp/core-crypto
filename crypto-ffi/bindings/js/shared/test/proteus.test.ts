import { runOnPlatform, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { expect } from "chai";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("proteus", () => {
    it("should initialize correctly", async () => {
        const result = await runOnPlatform(async () => {
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

        expect(result.lastResortPrekeyId).to.equal(u16MAX);
        expect(result.lastResortPrekey1).to.deep.equal(
            result.lastResortPrekey2
        );
    });

    it("new session from prekey should succeed", async () => {
        await runOnPlatform(async () => {
            const sessionId = crypto.randomUUID();
            const alice = await helpers.proteusInit();
            const bob = await helpers.proteusInit();
            await helpers.newProteusSessionFromPrekey(alice, bob, sessionId);
        });
    });

    it("new session from message should succeed", async () => {
        const message = "Hello, world!";
        const decryptedMessage = await runOnPlatform(async (message) => {
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
        expect(decryptedMessage).to.equal(message);
    });

    it("initializing same session twice should fail", async () => {
        const result = await runOnPlatform(async () => {
            const sessionId = crypto.randomUUID();
            const alice = await helpers.proteusInit();
            const bob = await helpers.proteusInit();
            // Session for alice
            await helpers.newProteusSessionFromPrekey(alice, bob, sessionId);
            // Session for bob
            const message = "Hello, world!";
            const decryptedMessage = await helpers.newProteusSessionFromMessage(
                alice,
                bob,
                sessionId,
                message
            );

            if (decryptedMessage != message) {
                throw new Error("Messages should match");
            }
            try {
                await helpers.newProteusSessionFromMessage(
                    alice,
                    bob,
                    sessionId,
                    message
                );
                throw new Error(
                    "Expected newProteusSessionFromMessage to reject"
                );
            } catch (err) {
                return ccModule.CoreCryptoError.Proteus.instanceOf(err);
            }
        });
        expect(result).to.equal(true);
    });
});
