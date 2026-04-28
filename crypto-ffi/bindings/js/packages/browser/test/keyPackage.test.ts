import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("key package", () => {
    it("can be created", async () => {
        const { threwError, wasDefined } = await browser.execute(async () => {
            const cc = await window.helpers.ccInit();

            let threwError = false;
            let keyPackage = undefined;
            try {
                keyPackage = await window.helpers.generateKeyPackage(cc);
            } catch {
                threwError = true;
            }

            const wasDefined = keyPackage !== null && keyPackage !== undefined;

            return { threwError, wasDefined };
        });

        await expect(threwError).toBe(false);
        await expect(wasDefined).toBe(true);
    });

    it("can be serialized", async () => {
        const { wasDefined, wasEmpty, roundtripMatches } =
            await browser.execute(async () => {
                const cc = await window.helpers.ccInit();
                const keyPackage = await window.helpers.generateKeyPackage(cc);

                const bytes = new Uint8Array(keyPackage.serialize());

                const wasDefined = bytes !== null && bytes !== undefined;
                const wasEmpty = bytes.byteLength === 0;

                const kp2 = new window.ccModule.KeyPackage(bytes.buffer);
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
            });

        await expect(wasDefined).toBe(true);
        await expect(wasEmpty).toBe(false);
        await expect(roundtripMatches).toBe(true);
    });

    it("can be retrieved in bulk", async () => {
        const { wasDefined, wasArray, arraySize, firstItemDefined } =
            await browser.execute(async () => {
                const cc = await window.helpers.ccInit();
                await window.helpers.generateKeyPackage(cc);

                const keyPackages = await cc.transaction(async (ctx) => {
                    return await ctx.getKeyPackages();
                });

                const wasDefined =
                    keyPackages !== null && keyPackages !== undefined;
                const wasArray = Array.isArray(keyPackages);
                const arraySize = keyPackages.length;
                const firstItemDefined =
                    keyPackages[1] !== null && keyPackages[0] !== undefined;

                return { wasDefined, wasArray, arraySize, firstItemDefined };
            });

        await expect(wasDefined).toBe(true);
        await expect(wasArray).toBe(true);
        await expect(arraySize).toBe(1);
        await expect(firstItemDefined).toBe(true);
    });

    it("can be removed", async () => {
        const { wasDefined, wasArray, arraySize } = await browser.execute(
            async () => {
                const clientId = window.helpers.newClientId();
                const cc = await window.helpers.ccInit({
                    withBasicCredential: false,
                    clientId,
                });

                const credential = window.ccModule.Credential.basic(
                    window.ccModule.ciphersuiteDefault(),
                    clientId
                );

                const keyPackages = await cc.transaction(async (ctx) => {
                    const credentialRef = await ctx.addCredential(credential);
                    // add a kp which will not be removed, so we have one left over
                    await ctx.generateKeyPackage(credentialRef);
                    // add a kp which will be removed
                    const keyPackage =
                        await ctx.generateKeyPackage(credentialRef);
                    // now remove that keypackage
                    await ctx.removeKeyPackage(keyPackage.ref());

                    return await ctx.getKeyPackages();
                });

                const wasDefined =
                    keyPackages !== null && keyPackages !== undefined;
                const wasArray = Array.isArray(keyPackages);
                const arraySize = keyPackages.length;

                return { wasDefined, wasArray, arraySize };
            }
        );

        await expect(wasDefined).toBe(true);
        await expect(wasArray).toBe(true);
        await expect(arraySize).toBe(1);
    });

    it("can be removed by credentialref", async () => {
        const KEYPACKAGES_PER_CREDENTIAL = 2;

        const { beforeRemovalArraySize, afterRemovalArraySize } =
            await browser.execute(async (KEYPACKAGES_PER_CREDENTIAL) => {
                const clientId = window.helpers.newClientId();
                const cc = await window.helpers.ccInit({
                    withBasicCredential: false,
                    clientId,
                });
                const credential1 = window.ccModule.Credential.basic(
                    window.ccModule.Ciphersuite
                        .Mls128Dhkemx25519Aes128gcmSha256Ed25519,
                    clientId
                );
                const credential2 = window.ccModule.Credential.basic(
                    window.ccModule.Ciphersuite
                        .Mls128Dhkemp256Aes128gcmSha256P256,
                    clientId
                );

                return await cc.transaction(async (ctx) => {
                    const cref1 = await ctx.addCredential(credential1);
                    const cref2 = await ctx.addCredential(credential2);

                    // we're going to generate keypackages for both credentials,
                    // then remove those packages for credential 2, leaving behind
                    // those for credential 1
                    for (const cref of [cref1, cref2]) {
                        for (let i = 0; i < KEYPACKAGES_PER_CREDENTIAL; i++) {
                            await ctx.generateKeyPackage(cref);
                        }
                    }

                    const kpsBeforeRemoval = await ctx.getKeyPackages();
                    const beforeRemovalArraySize = kpsBeforeRemoval.length;

                    // now remove all keypackages for one of the credentials
                    await ctx.removeKeyPackagesFor(cref1);

                    const kps = await ctx.getKeyPackages();
                    const afterRemovalArraySize = kps.length;
                    return {
                        beforeRemovalArraySize,
                        afterRemovalArraySize,
                    };
                });
            }, KEYPACKAGES_PER_CREDENTIAL);

        // 2 credentials with the same n keypackages each
        await expect(beforeRemovalArraySize).toBe(
            KEYPACKAGES_PER_CREDENTIAL * 2
        );
        await expect(afterRemovalArraySize).toBe(KEYPACKAGES_PER_CREDENTIAL);
    });
});
