import { ccInit, setup, teardown } from "./utils";
import { test, beforeEach, describe, expect, afterAll } from "bun:test";
import {
    CipherSuite,
    ciphersuiteDefault,
    ClientId,
    Credential,
    CredentialType,
} from "@wireapp/core-crypto/native";

beforeEach(async () => {
    await setup();
});

afterAll(async () => {
    await teardown();
});

describe("credentials", () => {
    test("basic credential can be created", async () => {
        const credential = Credential.basic(
            ciphersuiteDefault(),
            new ClientId(Buffer.from("any random client id here"))
        );
        expect(credential.type()).toEqual(CredentialType.Basic);
        expect(credential.earliestValidity()).toEqual(0n);
    });

    test("credential can be added", async () => {
        const cc = await ccInit();
        const allCredentials = await cc.transaction(async (ctx) => {
            return await ctx.getCredentials();
        });
        const [ref] = allCredentials;
        expect(ref).toBeDefined();
        expect(ref!.type()).toEqual(CredentialType.Basic);
        // saving causes the earliest validity to be updated
        expect(ref!.earliestValidity()).not.toEqual(0n);

        expect(allCredentials.length).toBe(1);
    });

    test("credential can be removed", async () => {
        const cc = await ccInit();

        const [ref] = await cc.transaction(async (ctx) => {
            return await ctx.getCredentials();
        });

        await cc.transaction(async (ctx) => {
            return await ctx.removeCredential(ref!);
        });

        const allCredentials = await cc.transaction(async (ctx) => {
            return await ctx.getCredentials();
        });
        expect(allCredentials.length).toBe(0);
    });

    test("credentials can be searched", async () => {
        const clientId = new ClientId(Buffer.from("any random client id here"));
        const ciphersuite1 = CipherSuite.Mls128Dhkemp256Aes128gcmSha256P256;
        const credential1 = Credential.basic(ciphersuite1, clientId);

        const ciphersuite2 =
            CipherSuite.Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519;
        const credential2 = Credential.basic(ciphersuite2, clientId);

        const cc = await ccInit({ withBasicCredential: false, clientId });

        await cc.transaction(async (ctx) => {
            await ctx.addCredential(credential1);
            await ctx.addCredential(credential2);
        });

        const results1 = await cc.transaction(async (ctx) => {
            return await ctx.findCredentials({
                ciphersuite: ciphersuite1,
            });
        });
        const results2 = await cc.transaction(async (ctx) => {
            return await ctx.findCredentials({
                ciphersuite: ciphersuite2,
            });
        });

        expect(results1.length).toBe(1);
        expect(results2.length).toBe(1);
        expect(results1[0]).not.toEqual(results2[0]);
    });
});
