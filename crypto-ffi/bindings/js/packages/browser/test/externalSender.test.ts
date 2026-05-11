import { expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { generateKeyPairSync } from "node:crypto";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

function generateEd25519JwkString(): string {
    const { publicKey } = generateKeyPairSync("ed25519");
    const jwk = publicKey.export({ format: "jwk" });
    return JSON.stringify(jwk);
}

describe("external sender", () => {
    it("parseJwk produces a sender usable in createConversation", async () => {
        const jwkString = generateEd25519JwkString();
        const [retrievedBytes, serializedBytes] = await browser.execute(
            async (jwkString) => {
                const jwk = new TextEncoder().encode(jwkString);
                const externalSender =
                    window.ccModule.ExternalSender.parseJwk(jwk);

                const alice = await window.helpers.ccInit();
                const conversationId = window.helpers.newConversationId();
                const retrievedKey = await alice.transaction(async (ctx) => {
                    const [credentialRef] = await ctx.getCredentials();
                    await ctx.createConversation(
                        conversationId,
                        credentialRef!,
                        externalSender
                    );
                    return await ctx.getExternalSender(conversationId);
                });

                return [
                    Array.from(retrievedKey.copyBytes()),
                    Array.from(externalSender.serialize()),
                ];
            },
            jwkString
        );

        await expect(retrievedBytes).toEqual(serializedBytes);
    });

    it("parsePublicKey accepts the bytes produced by serialize", async () => {
        const jwkString = generateEd25519JwkString();
        const equal = await browser.execute(async (jwkString) => {
            const jwk = new TextEncoder().encode(jwkString);
            const fromJwk = window.ccModule.ExternalSender.parseJwk(jwk);
            const fromBytes = window.ccModule.ExternalSender.parsePublicKey(
                fromJwk.serialize(),
                window.ccModule.SignatureScheme.Ed25519
            );
            return fromJwk.equals(fromBytes);
        }, jwkString);

        await expect(equal).toBe(true);
    });

    it("parseJwk rejects malformed bytes", async () => {
        const threw = await browser.execute(async () => {
            try {
                window.ccModule.ExternalSender.parseJwk(
                    new Uint8Array([0, 1, 2, 3])
                );
                return false;
            } catch {
                return true;
            }
        });

        await expect(threw).toBe(true);
    });
});
