import { ccInit, setup, teardown } from "./utils";
import { test, beforeEach, describe, expect, afterAll } from "bun:test";
import { ciphersuiteDefault, ClientId } from "@wireapp/core-crypto/native";
import {
    Ciphersuite,
    Credential,
    KeyPackage,
} from "@wireapp/core-crypto/native";

beforeEach(async () => {
    await setup();
});

afterAll(async () => {
    await teardown();
});

describe("key package", () => {
    test("can be created", async () => {
        const clientId = new ClientId(
            Buffer.from("any random client id here").buffer
        );
        const credential = Credential.basic(ciphersuiteDefault(), clientId);

        const cc = await ccInit(clientId);

        const credentialRef = await cc.transaction(async (ctx) => {
            return await ctx.addCredential(credential);
        });

        const keyPackage = await cc.transaction(async (ctx) => {
            return await ctx.generateKeyPackage(credentialRef);
        });

        expect(keyPackage).toBeDefined();
    });

    test("can be serialized", async () => {
        const clientId = new ClientId(
            Buffer.from("any random client id here").buffer
        );
        const credential = Credential.basic(ciphersuiteDefault(), clientId);

        const cc = await ccInit(clientId);

        const credentialRef = await cc.transaction(async (ctx) => {
            return await ctx.addCredential(credential);
        });

        const keyPackage = await cc.transaction(async (ctx) => {
            return await ctx.generateKeyPackage(credentialRef);
        });

        const bytes = new Uint8Array(keyPackage.serialize());

        expect(bytes).toBeDefined();
        expect(bytes).not.toBeEmpty();

        // roundtrip
        const kp2 = new KeyPackage(bytes.buffer);
        const bytes2 = new Uint8Array(kp2.serialize());

        expect(bytes2).toEqual(bytes);
    });

    test("can be retrieved in bulk", async () => {
        const clientId = new ClientId(
            Buffer.from("any random client id here").buffer
        );
        const credential = Credential.basic(ciphersuiteDefault(), clientId);

        const cc = await ccInit(clientId);

        const credentialRef = await cc.transaction(async (ctx) => {
            return await ctx.addCredential(credential);
        });

        await cc.transaction(async (ctx) => {
            await ctx.generateKeyPackage(credentialRef);
        });

        const keyPackages = await cc.transaction(async (ctx) => {
            return await ctx.getKeyPackages();
        });

        expect(keyPackages).toBeDefined();
        expect(keyPackages).toBeArrayOfSize(1);
        expect(keyPackages[0]).toBeDefined();
    });

    test("can be removed", async () => {
        const clientId = new ClientId(
            Buffer.from("any random client id here").buffer
        );
        const credential = Credential.basic(ciphersuiteDefault(), clientId);

        const cc = await ccInit(clientId);

        const credentialRef = await cc.transaction(async (ctx) => {
            return await ctx.addCredential(credential);
        });

        // add a kp which will not be removed, so we have one left over
        await cc.transaction(async (ctx) => {
            await ctx.generateKeyPackage(credentialRef);
        });

        // add a kp which will be removed
        const keyPackage = await cc.transaction(async (ctx) => {
            return await ctx.generateKeyPackage(credentialRef);
        });

        // now remove the keypackage
        await cc.transaction(async (ctx) => {
            await ctx.removeKeyPackage(keyPackage.ref());
        });

        const keyPackages = await cc.transaction(async (ctx) => {
            return await ctx.getKeyPackages();
        });

        expect(keyPackages).toBeDefined();
        expect(keyPackages).toBeArrayOfSize(1);
    });

    test("can be removed by credentialref", async () => {
        const clientId = new ClientId(
            Buffer.from("any random client id here").buffer
        );
        const credential1 = Credential.basic(
            Ciphersuite.Mls128Dhkemx25519Aes128gcmSha256Ed25519,
            clientId
        );
        const credential2 = Credential.basic(
            Ciphersuite.Mls128Dhkemp256Aes128gcmSha256P256,
            clientId
        );
        const cc = await ccInit(clientId);

        await cc.transaction(async (ctx) => {
            const cref1 = await ctx.addCredential(credential1);
            const cref2 = await ctx.addCredential(credential2);

            // we're going to generate keypackages for both credentials,
            // then remove those packages for credential 2, leaving behind those for credential 1
            const KEYPACKAGES_PER_CREDENTIAL = 2;
            for (const cref of [cref1, cref2]) {
                for (let i = 0; i < KEYPACKAGES_PER_CREDENTIAL; i++) {
                    await ctx.generateKeyPackage(cref);
                }
            }

            const kpsBeforeRemoval = await ctx.getKeyPackages();
            // 2 credentials with the same n keypackages each
            expect(kpsBeforeRemoval).toBeArrayOfSize(
                KEYPACKAGES_PER_CREDENTIAL * 2
            );

            // now remove all keypackages for one of the credentials
            await ctx.removeKeyPackagesFor(cref1);

            const kps = await ctx.getKeyPackages();
            expect(kps).toBeArrayOfSize(KEYPACKAGES_PER_CREDENTIAL);
        });
    });
});
