import { setup, teardown } from "./utils";
import { afterEach, test, beforeEach, describe, expect } from "bun:test";
import {
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
        const credential = Credential.basic(
            ciphersuiteDefault(),
            new ClientId(Buffer.from("any random client id here"))
        );
        expect(credential.type()).toEqual(CredentialType.Basic);
        expect(credential.earliest_validity()).toEqual(0n);
    });
});
