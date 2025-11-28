import { browser, expect } from "@wdio/globals";
import { ccInit, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("client identity", () => {
    it("get client public key should work", async () => {
        const alice = crypto.randomUUID();
        await ccInit(alice);
        const result = await browser.execute(async (clientName) => {
            const cc = window.ensureCcDefined(clientName);
            return (
                await cc.clientPublicKey(
                    window.defaultCipherSuite,
                    window.ccModule.CredentialType.Basic
                )
            ).byteLength;
        }, alice);
        expect(result).toBe(32);
    });

    it("requesting client key package should work", async () => {
        const alice = crypto.randomUUID();
        await ccInit(alice);
        const error = await browser.execute(async (clientName) => {
            const cc = window.ensureCcDefined(clientName);
            let error = false;
            try {
                const keypackage = await cc.transaction(async (ctx) => {
                    const [credentialRef] = await ctx.findCredentials({
                        ciphersuite: window.defaultCipherSuite,
                        credentialType: window.ccModule.CredentialType.Basic,
                    });
                    return await ctx.generateKeypackage(credentialRef!);
                });
                keypackage.serialize();
            } catch {
                error = true;
            }
            return error;
        }, alice);
        expect(error).toBe(false);
    });
});
