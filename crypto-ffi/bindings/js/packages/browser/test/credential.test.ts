import { browser } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("credentials", () => {
    it("basic credential can be created", async () => {
        const result = await browser.execute(async () => {
            const credential = window.ccModule.Credential.basic(
                window.ccModule.cipherSuiteDefault(),
                window.helpers.newClientId()
            );
            return {
                isBasicType:
                    credential.type() === window.ccModule.CredentialType.Basic,
                earliestValidity: credential.earliestValidity(),
            };
        });
        expect(result.isBasicType).toBe(true);
        expect(result.earliestValidity).toEqual(0n);
    });

    it("credential can be added", async () => {
        const result = await browser.execute(async () => {
            const cc = await window.helpers.ccInit();
            const allCredentials = await cc.getCredentials();
            const [ref] = allCredentials;
            return {
                isDefined: ref !== undefined,
                isBasicType:
                    ref!.type() === window.ccModule.CredentialType.Basic,
                earliestValidity: ref!.earliestValidity(),
                length: allCredentials.length,
            };
        });
        expect(result.isDefined).toBe(true);
        expect(result.isBasicType).toBe(true);
        // saving causes the earliest validity to be updated
        expect(result.earliestValidity).not.toEqual(0n);
        expect(result.length).toBe(1);
    });

    it("credential can be removed", async () => {
        const length = await browser.execute(async () => {
            const cc = await window.helpers.ccInit();
            const [ref] = await cc.getCredentials();
            await cc.transaction(async (ctx) => {
                return await ctx.removeCredential(ref!);
            });

            const allCredentials = await cc.getCredentials();
            return allCredentials.length;
        });
        expect(length).toBe(0);
    });

    it("credentials can be searched", async () => {
        const result = await browser.execute(async () => {
            const clientId = window.helpers.newClientId();
            const cipherSuite1 =
                window.ccModule.CipherSuite.Mls128Dhkemp256Aes128gcmSha256P256;
            const credential1 = window.ccModule.Credential.basic(
                cipherSuite1,
                clientId
            );

            const cipherSuite2 =
                window.ccModule.CipherSuite
                    .Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519;
            const credential2 = window.ccModule.Credential.basic(
                cipherSuite2,
                clientId
            );

            const cc = await window.helpers.ccInit({
                withBasicCredential: false,
                clientId,
            });

            await cc.transaction(async (ctx) => {
                await ctx.addCredential(credential1);
                await ctx.addCredential(credential2);
            });

            const results1 = await cc.findCredentials({
                cipherSuite: cipherSuite1,
            });
            const results2 = await cc.findCredentials({
                cipherSuite: cipherSuite2,
            });

            return {
                length1: results1.length,
                length2: results2.length,
                // We can't parse the actual CredentialRefs, so we compare a getter
                areEqual:
                    results1[0]!.cipherSuite() === results2[0]!.cipherSuite(),
            };
        });

        expect(result.length1).toBe(1);
        expect(result.length2).toBe(1);
        expect(result.areEqual).toBe(false);
    });

    it("can be checked", async () => {
        const result = await browser.execute(async () => {
            try {
                const cc = await window.helpers.ccInit({
                    withBasicCredential: true,
                    cipherSuite: window.defaultCipherSuite,
                    withPkiEnvironment: true,
                });
                await cc.transaction(async (ctx) => {
                    await ctx.checkCredentials();
                });
                return { success: true };
            } catch (err) {
                console.log(JSON.stringify(err));
                return { success: false };
            }
        });
        expect(result.success).toBe(true);
    });
});
