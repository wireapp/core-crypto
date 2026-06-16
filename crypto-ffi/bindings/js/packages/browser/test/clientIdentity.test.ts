import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("client identity", () => {
    it("Uuid.toString should work", async () => {
        const result = await browser.execute(() => {
            const rawUuid = window.crypto.randomUUID();
            const uuid = new window.ccModule.Uuid(rawUuid);

            return uuid.toString() === rawUuid;
        });
        expect(result).toBe(true);
    });

    it("get client public key should work", async () => {
        const result = await browser.execute(async () => {
            const cc = await window.helpers.ccInit();
            return (await cc.getCredentials())[0]!.publicKeyHash().byteLength;
        });
        expect(result).toBe(32);
    });

    it("requesting client key package should work", async () => {
        const threwError = await browser.execute(async () => {
            const cc = await window.helpers.ccInit();
            let threwError = false;
            try {
                const keypackage = await window.helpers.generateKeyPackage(cc);
                keypackage.serialize();
            } catch {
                threwError = true;
            }
            return threwError;
        });
        expect(threwError).toBe(false);
    });
});
