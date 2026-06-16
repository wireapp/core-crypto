import { Uuid } from "@wireapp/core-crypto/native";
import { ccInit, generateKeyPackage, setup, teardown } from "./utils";
import { test, afterEach, beforeEach, describe, expect } from "bun:test";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("client identity", () => {
    test("Uuid.toString should work", () => {
        const rawUuid = crypto.randomUUID();
        const uuid = new Uuid(rawUuid);

        expect(uuid.toString()).toBe(rawUuid);
    });

    test("get client public key should work", async () => {
        const cc = await ccInit();
        const result = (await cc.getCredentials())[0]!.publicKeyHash()
            .byteLength;
        expect(result).toBe(32);
    });

    test("requesting client key package should work", async () => {
        const cc = await ccInit();
        const keypackage = await generateKeyPackage(cc);
        keypackage.serialize();
    });
});
