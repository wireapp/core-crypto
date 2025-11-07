import { ccInit, setup, teardown } from "./utils";
import { afterEach, test, beforeEach, describe, expect } from "bun:test";
import {
    Ciphersuite,
    ciphersuiteDefault,
    ClientId,
    Credential,
    CredentialType,
} from "../../src/CoreCrypto";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("credentials", () => {
    test("basic credential can be created", async () => {
        const credential = credentialBasic(
            ciphersuiteDefault(),
            new ClientId(Buffer.from("any random client id here"))
        );
        expect(credential.type()).toEqual(CredentialType.Basic);
        expect(credential.earliest_validity()).toEqual(0n);
    });

    test("credential can be added", async () => {
        const clientId = new ClientId(Buffer.from("any random client id here"));
        const credential = credentialBasic(ciphersuiteDefault(), clientId);

        const cc = await ccInit(clientId);

        const ref = await cc.transaction(async (ctx) => {
            return await ctx.addCredential(credential);
        });

        expect(ref).toBeDefined();
        expect(ref.type()).toEqual(CredentialType.Basic);
        // saving causes the earliest validity to be updated
        expect(ref.earliest_validity()).not.toEqual(0n);

        const allCredentials = await cc.transaction(async (ctx) => {
            return await ctx.getCredentials();
        });
        expect(allCredentials.length).toBe(1);
    });

    test("credential can be removed", async () => {
        const clientId = new ClientId(Buffer.from("any random client id here"));
        const credential = credentialBasic(ciphersuiteDefault(), clientId);

        const cc = await ccInit(clientId);

        const ref = await cc.transaction(async (ctx) => {
            return await ctx.addCredential(credential);
        });

        await cc.transaction(async (ctx) => {
            return await ctx.removeCredential(ref);
        });

        const allCredentials = await cc.transaction(async (ctx) => {
            return await ctx.getCredentials();
        });
        expect(allCredentials.length).toBe(0);
    });

    test("credentials can be searched", async () => {
        const clientId = new ClientId(Buffer.from("any random client id here"));
        const ciphersuite1 =
            Ciphersuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256;
        const credential1 = Credential.basic(ciphersuite1, clientId);

        const ciphersuite2 =
            Ciphersuite.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        const credential2 = Credential.basic(ciphersuite2, clientId);

        const cc = await ccInit(clientId);

        await cc.transaction(async (ctx) => {
            await ctx.addCredential(credential1);
            await ctx.addCredential(credential2);
        });

        const results1 = await cc.transaction(async (ctx) => {
            return await ctx.findCredentials({ ciphersuite: ciphersuite1 });
        });
        const results2 = await cc.transaction(async (ctx) => {
            return await ctx.findCredentials({ ciphersuite: ciphersuite2 });
        });

        expect(results1.length).toBe(1);
        expect(results2.length).toBe(1);
        expect(results1[0]).not.toEqual(results2[0]);
    });
});
