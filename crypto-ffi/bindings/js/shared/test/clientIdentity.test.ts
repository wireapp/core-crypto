import { setup, teardown, runOnPlatform } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { expect } from "chai";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("client identity", () => {
    it("Uuid.toString should work", async () => {
        const result = await runOnPlatform(() => {
            const rawUuid = crypto.randomUUID();
            const uuid = new ccModule.Uuid(rawUuid);

            return uuid.toString() === rawUuid;
        });
        expect(result).to.equal(true);
    });

    it("get client public key should work", async () => {
        const result = await runOnPlatform(async () => {
            const cc = await helpers.ccInit();
            return (await cc.getCredentials())[0]!.publicKeyHash().byteLength;
        });
        expect(result).to.equal(32);
    });

    it("requesting client key package should work", async () => {
        const threwError = await runOnPlatform(async () => {
            const cc = await helpers.ccInit();
            let threwError = false;
            try {
                const keypackage = await helpers.generateKeyPackage(cc);
                keypackage.serialize();
            } catch {
                threwError = true;
            }
            return threwError;
        });
        expect(threwError).to.equal(false);
    });
});
