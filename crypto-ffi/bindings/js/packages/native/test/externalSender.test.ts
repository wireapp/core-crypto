import { generateKeyPairSync } from "node:crypto";
import { ccInit, newConversationId, setup, teardown } from "./utils";
import { test, beforeEach, describe, expect, afterAll } from "bun:test";
import { ExternalSender, SignatureScheme } from "@wireapp/core-crypto/native";

beforeEach(async () => {
    await setup();
});

afterAll(async () => {
    await teardown();
});

function generateEd25519Jwk(): Uint8Array {
    const { publicKey } = generateKeyPairSync("ed25519");
    const jwk = publicKey.export({ format: "jwk" });
    return new TextEncoder().encode(JSON.stringify(jwk));
}

describe("external sender", () => {
    test("parseJwk produces a sender usable in createConversation", async () => {
        const jwk = generateEd25519Jwk();
        const externalSender = ExternalSender.parseJwk(jwk);

        const cc = await ccInit();
        const conversationId = newConversationId();
        const [credentialRef] = await cc.getCredentials();
        const retrievedKey = await cc.transaction(async (ctx) => {
            await ctx.createConversation(
                conversationId,
                credentialRef!,
                externalSender
            );
            return await ctx.getExternalSender(conversationId);
        });

        expect(retrievedKey.serialize()).toEqual(externalSender.serialize());
    });

    test("parsePublicKey accepts the bytes produced by serialize", () => {
        const jwk = generateEd25519Jwk();
        const fromJwk = ExternalSender.parseJwk(jwk);
        const fromBytes = ExternalSender.parsePublicKey(
            fromJwk.serialize(),
            SignatureScheme.Ed25519
        );
        expect(fromJwk.equals(fromBytes)).toBe(true);
    });

    test("parseJwk rejects malformed bytes", () => {
        expect(() =>
            ExternalSender.parseJwk(new Uint8Array([0, 1, 2, 3]))
        ).toThrow();
    });
});
