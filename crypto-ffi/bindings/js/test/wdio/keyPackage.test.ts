import { browser, expect } from "@wdio/globals";
import { ccInit, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("key package", () => {
    it("can be created", async () => {
        const clientId = crypto.randomUUID();
        await ccInit(clientId, false);

        const { threwError, wasDefined } = await browser.execute(
            async (clientIdBytes) => {
                const encoder = new TextEncoder();
                const clientId = new window.ccModule.ClientId(
                    encoder.encode(clientIdBytes).buffer
                );

                const cc = window.cc.get(clientIdBytes)!;

                const credential = window.ccModule.credentialBasic(
                    window.ccModule.ciphersuiteDefault(),
                    clientId
                );

                const credentialRef = await cc.transaction(async (ctx) => {
                    return await ctx.addCredential(credential);
                });

                let threwError = false;
                let keyPackage = undefined;
                try {
                    keyPackage = await cc.transaction(async (ctx) => {
                        return await ctx.generateKeypackage(credentialRef);
                    });
                } catch {
                    threwError = true;
                }

                const wasDefined =
                    keyPackage !== null && keyPackage !== undefined;

                return { threwError, wasDefined };
            },
            clientId
        );

        expect(threwError).toBe(false);
        expect(wasDefined).toBe(true);
    });

    it("can be serialized", async () => {
        const clientId = crypto.randomUUID();
        await ccInit(clientId, false);

        const { wasDefined, wasEmpty, roundtripMatches } =
            await browser.execute(async (clientIdBytes) => {
                const encoder = new TextEncoder();
                const clientId = new window.ccModule.ClientId(
                    encoder.encode(clientIdBytes).buffer
                );

                const cc = window.cc.get(clientIdBytes)!;

                const credential = window.ccModule.credentialBasic(
                    window.ccModule.ciphersuiteDefault(),
                    clientId
                );

                const credentialRef = await cc.transaction(async (ctx) => {
                    return await ctx.addCredential(credential);
                });

                const keyPackage = await cc.transaction(async (ctx) => {
                    return await ctx.generateKeypackage(credentialRef);
                });
                const bytes = new Uint8Array(keyPackage.serialize());

                const wasDefined = bytes !== null && bytes !== undefined;
                const wasEmpty = bytes.byteLength === 0;

                const kp2 = new window.ccModule.Keypackage(bytes.buffer);
                const bytes2 = new Uint8Array(kp2.serialize());

                // JS in the browser doesn't have a natural way to compare Uint8Arrays,
                // which is just... extremely JS
                let roundtripMatches = bytes.length === bytes2.length;
                let index = 0;
                while (roundtripMatches && index < bytes.length) {
                    roundtripMatches =
                        roundtripMatches && bytes[index] === bytes2[index];
                    index += 1;
                }

                return { wasDefined, wasEmpty, roundtripMatches };
            }, clientId);

        expect(wasDefined).toBe(true);
        expect(wasEmpty).toBe(false);
        expect(roundtripMatches).toBe(true);
    });

    it("can be retrieved in bulk", async () => {
        const clientId = crypto.randomUUID();
        await ccInit(clientId, false);

        const { wasDefined, wasArray, arraySize, firstItemDefined } =
            await browser.execute(async (clientIdBytes) => {
                const encoder = new TextEncoder();
                const clientId = new window.ccModule.ClientId(
                    encoder.encode(clientIdBytes).buffer
                );

                const cc = window.cc.get(clientIdBytes)!;

                const credential = window.ccModule.credentialBasic(
                    window.ccModule.ciphersuiteDefault(),
                    clientId
                );

                const keyPackages = await cc.transaction(async (ctx) => {
                    const credentialRef = await ctx.addCredential(credential);
                    await ctx.generateKeypackage(credentialRef);
                    return await ctx.getKeypackages();
                });

                const wasDefined =
                    keyPackages !== null && keyPackages !== undefined;
                const wasArray = Array.isArray(keyPackages);
                const arraySize = keyPackages.length;
                const firstItemDefined =
                    keyPackages[1] !== null && keyPackages[0] !== undefined;

                return { wasDefined, wasArray, arraySize, firstItemDefined };
            }, clientId);

        expect(wasDefined).toBe(true);
        expect(wasArray).toBe(true);
        expect(arraySize).toBe(1);
        expect(firstItemDefined).toBe(true);
    });

    it("can be removed", async () => {
        const clientId = crypto.randomUUID();
        await ccInit(clientId, false);

        const { wasDefined, wasArray, arraySize } = await browser.execute(
            async (clientIdBytes) => {
                const encoder = new TextEncoder();
                const clientId = new window.ccModule.ClientId(
                    encoder.encode(clientIdBytes).buffer
                );

                const cc = window.cc.get(clientIdBytes)!;

                const credential = window.ccModule.credentialBasic(
                    window.ccModule.ciphersuiteDefault(),
                    clientId
                );

                const keyPackages = await cc.transaction(async (ctx) => {
                    const credentialRef = await ctx.addCredential(credential);
                    // add a kp which will not be removed, so we have one left over
                    await ctx.generateKeypackage(credentialRef);
                    // add a kp which will be removed
                    const keyPackage =
                        await ctx.generateKeypackage(credentialRef);
                    // now remove that keypackage
                    await ctx.removeKeypackage(keyPackage.ref());

                    return await ctx.getKeypackages();
                });

                const wasDefined =
                    keyPackages !== null && keyPackages !== undefined;
                const wasArray = Array.isArray(keyPackages);
                const arraySize = keyPackages.length;

                return { wasDefined, wasArray, arraySize };
            },
            clientId
        );

        expect(wasDefined).toBe(true);
        expect(wasArray).toBe(true);
        expect(arraySize).toBe(1);
    });

    it("can be removed by credentialref", async () => {
        const clientId = crypto.randomUUID();
        await ccInit(clientId, false);

        const KEYPACKAGES_PER_CREDENTIAL = 2;

        const { beforeRemovalArraySize, afterRemovalArraySize } =
            await browser.execute(
                async (clientIdBytes, KEYPACKAGES_PER_CREDENTIAL) => {
                    const encoder = new TextEncoder();
                    const clientId = new window.ccModule.ClientId(
                        encoder.encode(clientIdBytes).buffer
                    );

                    const credential1 = window.ccModule.credentialBasic(
                        window.ccModule.Ciphersuite
                            .Mls128Dhkemx25519Aes128gcmSha256Ed25519,
                        clientId
                    );
                    const credential2 = window.ccModule.credentialBasic(
                        window.ccModule.Ciphersuite
                            .Mls128Dhkemp256Aes128gcmSha256P256,
                        clientId
                    );

                    const cc = window.cc.get(clientIdBytes)!;

                    return await cc.transaction(async (ctx) => {
                        const cref1 = await ctx.addCredential(credential1);
                        const cref2 = await ctx.addCredential(credential2);

                        // we're going to generate keypackages for both credentials,
                        // then remove those packages for credential 2, leaving behind
                        // those for credential 1
                        for (const cref of [cref1, cref2]) {
                            for (
                                let i = 0;
                                i < KEYPACKAGES_PER_CREDENTIAL;
                                i++
                            ) {
                                await ctx.generateKeypackage(cref);
                            }
                        }

                        const kpsBeforeRemoval = await ctx.getKeypackages();
                        const beforeRemovalArraySize = kpsBeforeRemoval.length;

                        // now remove all keypackages for one of the credentials
                        await ctx.removeKeypackagesFor(cref1);

                        const kps = await ctx.getKeypackages();
                        const afterRemovalArraySize = kps.length;
                        return {
                            beforeRemovalArraySize,
                            afterRemovalArraySize,
                        };
                    });
                },
                clientId,
                KEYPACKAGES_PER_CREDENTIAL
            );

        // 2 credentials with the same n keypackages each
        expect(beforeRemovalArraySize).toBe(KEYPACKAGES_PER_CREDENTIAL * 2);
        expect(afterRemovalArraySize).toBe(KEYPACKAGES_PER_CREDENTIAL);
    });
});
