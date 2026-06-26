import { runOnPlatform, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { expect } from "chai";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("credentials", () => {
    it("basic credential can be created", async () => {
        const result = await runOnPlatform(async () => {
            const credential = ccModule.Credential.basic(
                ccModule.cipherSuiteDefault(),
                helpers.newClientId()
            );
            return {
                isBasicType:
                    credential.type() === ccModule.CredentialType.Basic,
                earliestValidity: credential.earliestValidity(),
            };
        });
        expect(result.isBasicType).to.equal(true);
        expect(result.earliestValidity).to.equal(0n);
    });

    it("credential can be added", async () => {
        const result = await runOnPlatform(async () => {
            const cc = await helpers.ccInit();
            const allCredentials = await cc.getCredentials();
            const [ref] = allCredentials;
            return {
                isDefined: ref !== undefined,
                isBasicType: ref!.type() === ccModule.CredentialType.Basic,
                earliestValidity: ref!.earliestValidity(),
                length: allCredentials.length,
            };
        });
        expect(result.isDefined).to.equal(true);
        expect(result.isBasicType).to.equal(true);
        // saving causes the earliest validity to be updated
        expect(result.earliestValidity).not.to.equal(0n);
        expect(result.length).to.equal(1);
    });

    it("credential can be removed", async () => {
        const length = await runOnPlatform(async () => {
            const cc = await helpers.ccInit();
            const [ref] = await cc.getCredentials();
            await cc.transaction(async (ctx) => {
                return await ctx.removeCredential(ref!);
            });

            const allCredentials = await cc.getCredentials();
            return allCredentials.length;
        });
        expect(length).to.equal(0);
    });

    it("credentials can be searched", async () => {
        const result = await runOnPlatform(async () => {
            const clientId = helpers.newClientId();
            const cipherSuite1 =
                ccModule.CipherSuite.Mls128Dhkemp256Aes128gcmSha256P256;
            const credential1 = ccModule.Credential.basic(
                cipherSuite1,
                clientId
            );

            const cipherSuite2 =
                ccModule.CipherSuite
                    .Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519;
            const credential2 = ccModule.Credential.basic(
                cipherSuite2,
                clientId
            );

            const cc = await helpers.ccInit({
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

        expect(result.length1).to.equal(1);
        expect(result.length2).to.equal(1);
        expect(result.areEqual).to.equal(false);
    });

    it("can be checked", async () => {
        const result = await runOnPlatform(async () => {
            try {
                const cc = await helpers.ccInit({
                    withBasicCredential: true,
                    cipherSuite: ccModule.cipherSuiteDefault(),
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
        expect(result.success).to.equal(true);
    });
});
